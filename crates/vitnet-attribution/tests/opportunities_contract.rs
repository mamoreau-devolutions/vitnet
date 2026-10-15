//! Direct, synthetic opportunity and retention contracts. No producer or corpus is run.
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[allow(dead_code)]
mod common;

fn query_node(id: u64, label: &str, truncated: bool) -> Value {
    json!({
        "node_id": id, "label": label, "label_bytes": if truncated { label.len() + 77 } else { label.len() },
        "truncated": truncated, "incoming_edges": if id == 4 { 3 } else { 0 }
    })
}

fn why_json(nodes: &[Value], reasons: &[&str]) -> Value {
    json!({
        "schema": "vitnet.dgml-why.v1", "generation": "witness-generation",
        "node": query_node(4, "Target", false),
        "paths": [{
            "root_kind": "zero_in_degree_candidate", "nodes": nodes, "reasons": reasons,
            "reason_bytes": reasons.iter().map(|s| s.len() as u64).collect::<Vec<_>>(),
            "reasons_truncated": reasons.iter().map(|_| false).collect::<Vec<_>>()
        }],
        "visited_nodes": 7, "examined_edges": 9, "repeated_nodes": 2, "missing_nodes": 1,
        "stop_reason": "complete", "elapsed_ms": 13, "caveat": "Shortest witnesses, not all prerequisites"
    })
}

fn incoming_json() -> Value {
    json!({
        "schema": "vitnet.dgml-incoming.v1", "generation": "incoming-generation",
        "node": query_node(4, "Target", false), "total_edges": 3,
        "edges": [{
            "ordinal": 7, "source_id": 1, "source": query_node(1, "Root", false), "target_id": 4,
            "reason": "registration", "reason_bytes": 12, "reason_truncated": false
        }, {
            "ordinal": 8, "source_id": 2, "source": query_node(2, "Alternative", false), "target_id": 4,
            "reason": "call", "reason_bytes": 4, "reason_truncated": false
        }, {
            "ordinal": 9, "source_id": 99, "source": null, "target_id": 4,
            "reason": "missing source", "reason_bytes": 14, "reason_truncated": false
        }],
        "next_after_edge": null, "stop_reason": "complete", "elapsed_ms": 17,
        "caveat": "Parallel edges and conjunctive alternatives are retained"
    })
}

fn retention_evidence() -> Evidence {
    let mut e = evidence();
    e.sources = vec![
        source(
            "Root",
            Some("Emitter"),
            &[
                "ModuleInitializer",
                "RegisterService(typeof(IService))",
                "JsonSerializable(typeof(Target))",
                "ModuleInitializer",
            ],
        ),
        source("Target", None, &[]),
        source("Alternative", None, &["RegisterService"]),
    ];
    e.mappings = e
        .sources
        .iter()
        .map(|s| Mapping {
            stream: "Methods".into(),
            identity: s.type_name.clone(),
            assembly: "App".into(),
            source_paths: vec![s.path.clone()],
            basis: "synthetic explicit declaration".into(),
        })
        .collect();
    e
}

fn annotation(e: &Evidence, why: &Value, incoming: &Value) -> vitnet_attribution::RetentionReport {
    annotate_retention(
        e,
        serde_json::from_value::<WhyReport>(why.clone()).unwrap(),
        serde_json::from_value::<IncomingReport>(incoming.clone()).unwrap(),
    )
}

fn preserve(report: &vitnet_attribution::RetentionReport, why: &Value, incoming: &Value) {
    assert_eq!(serde_json::to_value(&report.witness).unwrap(), *why);
    assert_eq!(
        serde_json::to_value(&report.alternative_incoming).unwrap(),
        *incoming
    );
    assert_eq!(report.schema, "vitnet.attribution-retention.v1");
    assert_eq!(
        report.caveats,
        [
            "Compiler reachability is not evidence of runtime execution; lazy factories can still retain code.",
            "Annotations are source/name candidates, not proof that one registration is the sole retainer. Full original paths and reasons are preserved.",
            "Primary/Secondary dependencies may be conjunctive. Paged incoming alternatives and bounded shortest witnesses are not all removal prerequisites.",
            "Witness and incoming queries each expose their own limits and completeness; neither predicts reclaimed bytes.",
            "Source anchors retain at most 8 declaration previews and 12 attributes of 256 bytes per declaration. Preview truncation/counts are explicit; complete declarations remain in captured source catalogs.",
        ]
    );
}

#[test]
fn annotated_retention_preserves_original_witness_and_alternatives() {
    let e = retention_evidence();
    let why = why_json(
        &[query_node(1, "Root", false), query_node(4, "Target", false)],
        &["call"],
    );
    let incoming = incoming_json();
    let r = annotation(&e, &why, &incoming);
    preserve(&r, &why, &incoming);
    assert_eq!(r.annotated_paths.len(), 1);
    let path = &r.annotated_paths[0];
    assert_eq!(path.root_kind, "zero_in_degree_candidate");
    assert_eq!(path.collapsed_unmapped_nodes, 0);
    assert_eq!(
        path.anchors
            .iter()
            .map(|a| (a.node_id, a.producer_label.as_str()))
            .collect::<Vec<_>>(),
        [(1, "Root"), (4, "Target")]
    );
    assert_eq!(path.anchors[0].sources.status, "asserted");
    assert_eq!(path.anchors[0].sources.assemblies, ["App"]);
    assert_eq!(
        serde_json::to_value(&path.anchors[0].sources.sources).unwrap(),
        serde_json::to_value(&e.sources[..1]).unwrap()
    );
    assert_eq!(
        path.anchors[0].possible_mechanisms,
        [
            "generated_code",
            "module_initializer",
            "serialization_root_annotation",
            "service_registration_annotation"
        ]
    );
    assert_eq!(path.anchors[1].possible_mechanisms, Vec::<String>::new());
    assert_eq!(
        r.incoming_anchors
            .iter()
            .map(|a| a.node_id)
            .collect::<Vec<_>>(),
        [1, 2]
    );
    assert_eq!(
        r.incoming_anchors[1].possible_mechanisms,
        ["service_registration_annotation"]
    );
    assert_eq!(r.alternative_incoming.total_edges, 3);
    assert_eq!(r.alternative_incoming.edges[2].source_id, 99);
    assert!(r.alternative_incoming.edges[2].source.is_none());
}

#[test]
fn annotated_retention_source_previews_expose_counts_and_truncation() {
    let why = why_json(
        &[query_node(1, "Root", false), query_node(4, "Target", false)],
        &["call"],
    );
    let incoming = incoming_json();
    // The new bounded source projection must truthfully expose its count/truncation.
    for count in [0, 1, 7, 8, 9] {
        let mut e = retention_evidence();
        e.sources = (0..count)
            .map(|n| {
                let mut s = source("Root", None, &[]);
                s.line = n + 1;
                s.end_line = n + 4;
                if count == 9 && n == 8 {
                    s.attributes.push("ModuleInitializer".into());
                }
                s
            })
            .collect();
        let r = annotation(&e, &why, &incoming);
        preserve(&r, &why, &incoming);
        let a = &r.incoming_anchors[0];
        assert_eq!(a.total_source_candidates, usize::try_from(count).unwrap());
        assert_eq!(a.source_preview_truncated, count > 8);
        assert_eq!(
            a.sources.sources.len(),
            usize::try_from(count).unwrap().min(8)
        );
        assert_eq!(
            a.sources.sources.iter().map(|s| s.line).collect::<Vec<_>>(),
            (1..=count.min(8)).collect::<Vec<_>>()
        );
        assert_eq!(
            a.possible_mechanisms,
            if count == 9 {
                vec!["module_initializer"]
            } else {
                vec![]
            }
        );
    }
    for attributes in [11, 12, 13] {
        let mut e = retention_evidence();
        e.sources[0].attributes = (0..attributes).map(|n| format!("Other{n}")).collect();
        // A mechanism beyond the preview cap remains a possibility, not a sole cause.
        if attributes == 13 {
            e.sources[0].attributes[12] = "ModuleInitializer".into();
        }
        let r = annotation(&e, &why, &incoming);
        preserve(&r, &why, &incoming);
        let a = &r.incoming_anchors[0];
        assert_eq!(a.total_source_candidates, 1);
        assert_eq!(a.source_preview_truncated, attributes > 12);
        assert_eq!(
            a.sources.sources[0].attributes,
            (0..attributes.min(12))
                .map(|n| format!("Other{n}"))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            a.possible_mechanisms,
            if attributes == 13 {
                vec!["generated_code", "module_initializer"]
            } else {
                vec!["generated_code"]
            }
        );
    }
    for (attribute, preview, truncated) in [
        ("x".repeat(255), "x".repeat(255), false),
        ("x".repeat(256), "x".repeat(256), false),
        ("x".repeat(257), "x".repeat(256), true),
        (format!("{}é", "x".repeat(255)), "x".repeat(255), true),
    ] {
        let mut e = retention_evidence();
        e.sources[0].attributes = vec![attribute];
        let r = annotation(&e, &why, &incoming);
        preserve(&r, &why, &incoming);
        let a = &r.incoming_anchors[0];
        assert_eq!(a.source_preview_truncated, truncated);
        assert_eq!(a.total_source_candidates, 1);
        assert_eq!(a.sources.sources[0].attributes, [preview]);
    }
}

#[test]
fn annotated_retention_no_path_keeps_query_stop_evidence() {
    let e = retention_evidence();
    for stop in [
        "complete",
        "max_depth",
        "max_visited",
        "max_edges",
        "timeout",
        "cancelled",
    ] {
        let mut why = why_json(&[], &[]);
        why["paths"] = json!([]);
        why["stop_reason"] = json!(stop);
        why["visited_nodes"] = json!(3);
        why["examined_edges"] = json!(2);
        let mut incoming = incoming_json();
        incoming["total_edges"] = json!(0);
        incoming["edges"] = json!([]);
        let r = annotation(&e, &why, &incoming);
        preserve(&r, &why, &incoming);
        assert!(
            r.witness.paths.is_empty()
                && r.annotated_paths.is_empty()
                && r.incoming_anchors.is_empty()
        );
        assert_eq!(r.witness.stop_reason, stop);
        assert_eq!((r.witness.visited_nodes, r.witness.examined_edges), (3, 2));
    }
}

#[test]
fn annotated_retention_conjunctive_reasons_remain_conjunctive() {
    let e = retention_evidence();
    let mut why = why_json(
        &[query_node(1, "Root", false), query_node(4, "Target", false)],
        &["Primary"],
    );
    why["paths"].as_array_mut().unwrap().push(json!({
        "root_kind": "zero_in_degree_candidate",
        "nodes": [query_node(2, "Alternative", false), query_node(4, "Target", false)],
        "reasons": ["Secondary"], "reason_bytes": [9], "reasons_truncated": [false]
    }));
    let mut incoming = incoming_json();
    incoming["edges"][0]["reason"] = json!("Primary");
    incoming["edges"][0]["reason_bytes"] = json!(7);
    incoming["edges"][1]["reason"] = json!("Secondary");
    incoming["edges"][1]["reason_bytes"] = json!(9);
    let r = annotation(&e, &why, &incoming);
    preserve(&r, &why, &incoming);
    assert_eq!(r.witness.paths.len(), 2);
    assert_eq!(r.witness.paths[0].reasons, ["Primary"]);
    assert_eq!(r.witness.paths[1].reasons, ["Secondary"]);
    assert_eq!(r.annotated_paths[0].collapsed_unmapped_nodes, 0);
    assert_eq!(r.annotated_paths[1].collapsed_unmapped_nodes, 0);
    assert_eq!(
        r.annotated_paths[0]
            .anchors
            .iter()
            .map(|a| a.node_id)
            .collect::<Vec<_>>(),
        [1, 4]
    );
    assert_eq!(
        r.annotated_paths[1]
            .anchors
            .iter()
            .map(|a| a.node_id)
            .collect::<Vec<_>>(),
        [2, 4]
    );
    assert_eq!(
        r.alternative_incoming
            .edges
            .iter()
            .map(|e| e.reason.as_str())
            .collect::<Vec<_>>(),
        ["Primary", "Secondary", "missing source"]
    );
    assert!(
        r.caveats.iter().any(
            |s| s.contains("may be conjunctive") && s.contains("not all removal prerequisites")
        )
    );
    assert!(
        r.caveats
            .iter()
            .any(|s| s.contains("not proof") && s.contains("sole retainer"))
    );
}

#[test]
fn annotation_anchor_collapse_never_discards_original_graph_evidence() {
    let e = retention_evidence();
    let incoming = incoming_json();
    for (nodes, reasons, expected_anchors, collapsed) in [
        (
            vec![
                query_node(1, "Root", false),
                query_node(30, "opaque-1", false),
                query_node(31, "opaque-2", false),
                query_node(4, "Target", false),
            ],
            vec!["edge1", "edge2", "edge3"],
            vec![1, 4],
            2,
        ),
        (
            vec![
                query_node(30, "opaque-1", false),
                query_node(31, "opaque-2", false),
            ],
            vec!["edge"],
            vec![],
            2,
        ),
        (vec![query_node(4, "Target", false)], vec![], vec![4], 0),
    ] {
        let why = why_json(&nodes, &reasons);
        let r = annotation(&e, &why, &incoming);
        preserve(&r, &why, &incoming);
        assert_eq!(
            r.annotated_paths[0]
                .anchors
                .iter()
                .map(|a| a.node_id)
                .collect::<Vec<_>>(),
            expected_anchors
        );
        assert_eq!(r.annotated_paths[0].collapsed_unmapped_nodes, collapsed);
        assert_eq!(r.witness.paths[0].reasons.len(), reasons.len());
    }
    // Independent witness alternatives must retain their own anchor/collapse ledgers.
    let mut why = why_json(
        &[query_node(1, "Root", false), query_node(4, "Target", false)],
        &["call"],
    );
    why["paths"].as_array_mut().unwrap().push(json!({
        "root_kind": "nativeaot_root", "nodes": [query_node(2, "Alternative", false), query_node(31, "opaque", false), query_node(4, "Target", false)],
        "reasons": ["registration", "call"], "reason_bytes": [12, 4], "reasons_truncated": [false, false]
    }));
    let r = annotation(&e, &why, &incoming);
    preserve(&r, &why, &incoming);
    assert_eq!(r.annotated_paths.len(), 2);
    assert_eq!(r.annotated_paths[1].root_kind, "nativeaot_root");
    assert_eq!(
        r.annotated_paths[1]
            .anchors
            .iter()
            .map(|a| a.node_id)
            .collect::<Vec<_>>(),
        [2, 4]
    );
    assert_eq!(r.annotated_paths[1].collapsed_unmapped_nodes, 1);
}

#[test]
fn truncated_retention_labels_use_explicit_unmapped_basis() {
    let e = retention_evidence();
    // Even an exact displayed spelling of a captured declaration is untrusted if truncated.
    let why = why_json(
        &[
            query_node(1, "Root", true),
            query_node(3, "opaque-\u{fffd}", false),
            query_node(4, "Target", false),
        ],
        &["original edge", "original reason"],
    );
    let mut incoming = incoming_json();
    incoming["edges"][0]["source"] = query_node(1, "Root", true);
    incoming["edges"][1]["source"] = query_node(2, "opaque-\u{fffd}", false);
    let r = annotation(&e, &why, &incoming);
    preserve(&r, &why, &incoming);
    assert_eq!(r.annotated_paths[0].collapsed_unmapped_nodes, 2);
    assert_eq!(
        r.annotated_paths[0]
            .anchors
            .iter()
            .map(|a| a.node_id)
            .collect::<Vec<_>>(),
        [4]
    );
    let truncated = &r.incoming_anchors[0];
    assert_eq!(truncated.sources.status, "unmapped_truncated_label");
    assert_eq!(
        truncated.sources.basis,
        "A bounded preview cannot establish a complete symbol association"
    );
    assert!(
        truncated.sources.assemblies.is_empty()
            && truncated.sources.sources.is_empty()
            && truncated.possible_mechanisms.is_empty()
    );
    assert_eq!(
        (truncated.node_id, truncated.producer_label.as_str()),
        (1, "Root")
    );
    assert_eq!(r.incoming_anchors[1].sources.status, "unmapped");
    assert!(
        r.incoming_anchors[1].sources.sources.is_empty()
            && r.incoming_anchors[1].possible_mechanisms.is_empty()
    );
    assert!(r.witness.paths[0].nodes[0].truncated);
    assert_eq!(r.witness.paths[0].nodes[1].label, "opaque-\u{fffd}");
}

#[test]
fn retention_generations_limits_and_caveats_survive_annotation() {
    let e = retention_evidence();
    for stop in ["max_depth", "max_paths", "max_visited", "max_edges"] {
        let mut why = why_json(
            &[query_node(1, "Root", false), query_node(4, "Target", false)],
            &["bounded"],
        );
        why["stop_reason"] = json!(stop);
        why["paths"][0]["reason_bytes"] = json!([999]);
        why["paths"][0]["reasons_truncated"] = json!([true]);
        let mut incoming = incoming_json();
        incoming["edges"].as_array_mut().unwrap().truncate(1);
        incoming["stop_reason"] = json!("limit");
        incoming["next_after_edge"] = json!(7);
        incoming["edges"][0]["reason_truncated"] = json!(true);
        incoming["edges"][0]["reason_bytes"] = json!(777);
        let r = annotation(&e, &why, &incoming);
        preserve(&r, &why, &incoming);
        assert_eq!(r.witness.generation, "witness-generation");
        assert_eq!(r.alternative_incoming.generation, "incoming-generation");
        assert_eq!(
            (
                r.witness.visited_nodes,
                r.witness.examined_edges,
                r.witness.repeated_nodes,
                r.witness.missing_nodes
            ),
            (7, 9, 2, 1)
        );
        assert_eq!(r.witness.stop_reason, stop);
        assert_eq!(r.witness.paths[0].reason_bytes, [999]);
        assert_eq!(r.witness.paths[0].reasons_truncated, [true]);
        assert_eq!(
            (
                r.alternative_incoming.total_edges,
                r.alternative_incoming.edges.len(),
                r.alternative_incoming.next_after_edge
            ),
            (3, 1, Some(7))
        );
        assert_eq!(r.alternative_incoming.stop_reason, "limit");
        assert!(r.alternative_incoming.edges[0].reason_truncated);
        assert_eq!(r.alternative_incoming.edges[0].reason_bytes, 777);
        assert_eq!(
            (r.witness.elapsed_ms, r.alternative_incoming.elapsed_ms),
            (13, 17)
        );
    }
}

fn write_evidence(directory: &Path, e: &Evidence) -> PathBuf {
    let path = directory.join("evidence.json");
    fs::write(&path, serde_json::to_vec(e).unwrap()).unwrap();
    path
}

fn graph_fixture() -> (tempfile::TempDir, PathBuf, PathBuf, String) {
    let temp = tempfile::tempdir().unwrap();
    let graph_path = temp.path().join("graph.dgml");
    fs::write(
        &graph_path,
        r#"<DirectedGraph><Nodes>
        <Node Id="0" Label="Root"/><Node Id="1" Label="Target"/>
        <Node Id="2" Label="Alternative"/><Node Id="3" Label="Detached"/>
        </Nodes><Links><Link Source="0" Target="1" Reason="call"/>
        <Link Source="2" Target="1" Reason="registration"/></Links></DirectedGraph>"#,
    )
    .unwrap();
    let graph = build_index(
        &graph_path,
        &IndexOptions {
            cache_root: temp.path().join("cache"),
            memory_limit: 16 << 20,
            selected_entry: None,
            strict_hash: true,
            control: IndexControl::default(),
        },
    )
    .unwrap();
    let mut e = retention_evidence();
    for s in &mut e.sources {
        s.path = temp.path().join(&s.path);
        fs::write(&s.path, "class Synthetic {}").unwrap();
    }
    for m in &mut e.mappings {
        m.source_paths = vec![temp.path().join(format!("{}.cs", m.identity))];
    }
    e.artifacts.push(Artifact {
        kind: "scan_index".into(),
        path: graph.index_directory.clone(),
        revision: None,
        blake3: None,
    });
    let manifest = write_evidence(temp.path(), &e);
    let output = temp.path().join("attribution");
    let imported = import(&manifest, &output, MEMORY, false).unwrap();
    assert_eq!(
        imported
            .artifacts
            .iter()
            .find(|a| a.kind == "scan_index")
            .unwrap()
            .graph_generation
            .as_deref(),
        Some(graph.generation.as_str())
    );
    (temp, output, graph.index_directory, graph.generation)
}

fn normalize_query_timing(mut value: Value) -> Value {
    value["witness"]
        .as_object_mut()
        .unwrap()
        .remove("elapsed_ms");
    value["alternative_incoming"]
        .as_object_mut()
        .unwrap()
        .remove("elapsed_ms");
    value
}

#[test]
fn explain_matches_public_witness_and_incoming_composition() {
    let (_temp, output, graph_path, generation) = graph_fixture();
    let before = fs::read(output.join("index.json")).unwrap();
    let options = WhyOptions {
        max_paths: 1,
        preview_bytes: 128,
        generation: Some(generation.clone()),
        ..WhyOptions::default()
    };
    let evidence = vitnet_attribution::open_index(&output, MEMORY)
        .unwrap()
        .evidence;
    let mut graph = GraphSession::open(&graph_path, MEMORY / 2).unwrap();
    let why = graph.why(1, &options).unwrap();
    let incoming = graph
        .incoming(
            1,
            &IncomingOptions {
                limit: 1,
                preview_bytes: 128,
                generation: Some(generation.clone()),
                timeout_ms: options.timeout_ms,
                after_edge: None,
            },
        )
        .unwrap();
    let expected = annotate_retention(&evidence, why, incoming);
    drop(graph);
    let actual = explain(&output, 1, "scan_index", MEMORY, &options, 1).unwrap();
    assert_eq!(
        normalize_query_timing(serde_json::to_value(&actual).unwrap()),
        normalize_query_timing(serde_json::to_value(&expected).unwrap())
    );
    assert_eq!(actual.witness.node.node_id, 1);
    assert_eq!(actual.witness.node.label, "Target");
    assert_eq!(actual.witness.generation, generation);
    assert_eq!(actual.alternative_incoming.generation, generation);
    assert_eq!(actual.alternative_incoming.total_edges, 2);
    assert_eq!(actual.alternative_incoming.edges.len(), 1);
    assert_eq!(actual.alternative_incoming.stop_reason, "limit");
    assert!(actual.alternative_incoming.next_after_edge.is_some());
    assert_eq!(actual.witness.paths.len(), 1);
    assert_eq!(actual.witness.paths[0].nodes.last().unwrap().node_id, 1);
    assert_eq!(fs::read(output.join("index.json")).unwrap(), before);
    code(
        explain(&output, 999, "scan_index", MEMORY, &options, 1),
        "dgml.query.node",
    );
    code(
        explain(&output, 1, "scan_index", MEMORY, &options, 0),
        "resource.memory_limit",
    );
}

#[test]
fn explain_rejects_missing_or_ambiguous_graph_selection() {
    let temp = tempfile::tempdir().unwrap();
    let manifest = write_evidence(temp.path(), &evidence());
    let output = temp.path().join("empty-index");
    import(&manifest, &output, MEMORY, false).unwrap();
    for graph in ["scan_index", "codegen_index"] {
        code(
            explain(&output, 1, graph, MEMORY, &WhyOptions::default(), 2),
            "attribution.graph.missing",
        );
    }
    code(
        explain(&output, 1, "unknown", MEMORY, &WhyOptions::default(), 2),
        "attribution.graph.kind",
    );
    let (_temp, output, _, _) = graph_fixture();
    code(
        explain(
            &output,
            1,
            "codegen_index",
            MEMORY,
            &WhyOptions::default(),
            2,
        ),
        "attribution.graph.missing",
    );
    let path = output.join("index.json");
    let mut index = vitnet_attribution::open_index(&output, MEMORY).unwrap();
    let duplicate = index
        .artifacts
        .iter()
        .find(|a| a.kind == "scan_index")
        .unwrap()
        .clone();
    index.artifacts.push(duplicate);
    fs::write(&path, serde_json::to_vec(&index).unwrap()).unwrap();
    let before = fs::read(&path).unwrap();
    code(
        explain(&output, 1, "scan_index", MEMORY, &WhyOptions::default(), 2),
        "attribution.graph.missing",
    );
    assert_eq!(fs::read(path).unwrap(), before);
}

#[test]
fn explain_rejects_changed_captured_graph_generation() {
    let (_temp, output, _, generation) = graph_fixture();
    let path = output.join("index.json");
    let before = fs::read(&path).unwrap();
    code(
        explain(
            &output,
            1,
            "scan_index",
            MEMORY,
            &WhyOptions {
                generation: Some(format!("{generation}-not-current")),
                ..WhyOptions::default()
            },
            2,
        ),
        "attribution.graph.stale",
    );
    assert_eq!(fs::read(&path).unwrap(), before);
    for captured in [None, Some(format!("{generation}-stale"))] {
        let mut index: vitnet_attribution::AttributionIndex =
            serde_json::from_slice(&before).unwrap();
        index
            .artifacts
            .iter_mut()
            .find(|a| a.kind == "scan_index")
            .unwrap()
            .graph_generation = captured;
        fs::write(&path, serde_json::to_vec(&index).unwrap()).unwrap();
        let stale = fs::read(&path).unwrap();
        code(
            explain(&output, 1, "scan_index", MEMORY, &WhyOptions::default(), 2),
            "attribution.graph.stale",
        );
        assert_eq!(fs::read(&path).unwrap(), stale);
    }
}

use serde_json::{Value, json};
use vitnet_attribution::model::{
    Artifact, Assembly, EVIDENCE_SCHEMA, Evidence, Generator, GeneratorChecksum, GeneratorLink,
    GeneratorOutput, GeneratorRun, Mapping, Package, Source,
};
use vitnet_attribution::{
    AttributionError, Budget, CapabilityRule, Opportunity, OpportunityCollector, OpportunityPolicy,
    OpportunityReport, POLICY_SCHEMA, PatternRule, SourceMatch, SymbolLookup, SymbolSidecar,
    annotate_retention, explain, import, validate_policy,
};
use vitnet_dgml::{
    GraphSession, IncomingOptions, IncomingReport, IndexControl, IndexOptions, WhyOptions,
    WhyReport, build_index,
};
use vitnet_mstat::CoalescedIdentity;

const MEMORY: u64 = 128 << 20;
const MIB: u64 = 1 << 20;

fn evidence() -> Evidence {
    Evidence {
        schema: EVIDENCE_SCHEMA.into(),
        ..Evidence::default()
    }
}

fn policy() -> OpportunityPolicy {
    OpportunityPolicy {
        schema: POLICY_SCHEMA.into(),
        ..OpportunityPolicy::default()
    }
}

fn rule(id: &str, terms: &[&str], assemblies: &[&str]) -> PatternRule {
    PatternRule {
        id: id.into(),
        title: format!("Investigate {id}"),
        kind: "generated_pattern".into(),
        contains: terms.iter().map(|s| (*s).into()).collect(),
        assemblies: assemblies.iter().map(|s| (*s).into()).collect(),
        investigation: "Inspect retention; no savings claim".into(),
    }
}

fn capability(id: &str, assemblies: &[&str]) -> CapabilityRule {
    CapabilityRule {
        id: id.into(),
        title: "Alternative implementations".into(),
        assemblies: assemblies.iter().map(|s| (*s).into()).collect(),
        investigation: "Verify behavior and registrations".into(),
    }
}

fn row(stream: &str, name: &str, bytes: u64, accounted: bool) -> CoalescedIdentity {
    CoalescedIdentity {
        stream: stream.into(),
        accounted,
        identity: name.into(),
        raw_identity_blake3: blake3::hash(name.as_bytes()).to_hex().to_string(),
        identity_lossy: false,
        bytes,
        records: 99,
    }
}

fn association(status: &str, assemblies: &[&str]) -> SourceMatch {
    SourceMatch {
        status: status.into(),
        basis: "Independent synthetic association evidence".into(),
        assemblies: assemblies.iter().map(|s| (*s).into()).collect(),
        sources: Vec::new(),
    }
}

fn collect(
    evidence: &Evidence,
    policy: Option<&OpportunityPolicy>,
    rows: &[(CoalescedIdentity, SourceMatch, u64)],
) -> OpportunityReport {
    let mut collector = OpportunityCollector::new(evidence, policy, MEMORY).unwrap();
    for (entry, sources, ordinal) in rows {
        collector.observe(entry, sources, *ordinal).unwrap();
    }
    collector.finish().unwrap()
}

fn streams(entries: &[(&str, u64)]) -> BTreeMap<String, u64> {
    entries.iter().map(|(s, n)| ((*s).into(), *n)).collect()
}

fn finding<'a>(report: &'a OpportunityReport, id: &str) -> &'a Opportunity {
    report
        .opportunities
        .iter()
        .find(|f| f.id == id)
        .unwrap_or_else(|| {
            panic!(
                "missing finding {id}; got {:?}",
                report
                    .opportunities
                    .iter()
                    .map(|f| &f.id)
                    .collect::<Vec<_>>()
            )
        })
}

fn budget<'a>(
    report: &'a OpportunityReport,
    dimension: &str,
    name: &str,
    target: &str,
    tier: &str,
) -> &'a Budget {
    report
        .budgets
        .iter()
        .find(|b| {
            b.dimension == dimension
                && b.name == name
                && b.target == target
                && b.evidence_tier == tier
        })
        .unwrap_or_else(|| {
            panic!(
                "missing budget ({dimension},{name},{target},{tier}); actual ledger: {:?}",
                report.budgets
            )
        })
}

fn code<T: std::fmt::Debug>(result: Result<T, AttributionError>, expected: &str) {
    assert_eq!(result.unwrap_err().diagnostic.code, expected);
}

fn origin(assembly: &str, package: &str, role: &str, target: &str) -> Mapping {
    Mapping {
        stream: "package".into(),
        identity: package.into(),
        assembly: assembly.into(),
        source_paths: Vec::new(),
        basis: format!("assets_resolved_{role}:{target}"),
    }
}

fn source(name: &str, generated: Option<&str>, attributes: &[&str]) -> Source {
    Source {
        assembly: "App".into(),
        type_name: name.into(),
        path: PathBuf::from(format!("{name}.cs")),
        line: 1,
        end_line: 4,
        kind: "class".into(),
        generated_by: generated.map(str::to_owned),
        attributes: attributes.iter().map(|s| (*s).into()).collect(),
        ..Source::default()
    }
}

fn expected_limitations() -> Vec<&'static str> {
    vec![
        "Findings overlap. Never sum cohort bytes or interpret them as removable or physical bytes.",
        "Assembly budgets partition each stream by association tier. Ambiguous/unmapped identities are not charged to every candidate.",
        "Package budgets reconcile separately within each target. Do not sum targets; package inventory routes are not compiler-retention paths.",
        "Specialized resources/frozen objects and metadata lower bounds overlap additive Blobs; they are not extra budgets.",
        "Attributes are source occurrences, not proof a generator executed, an output is compiled, or a registration is the sole retainer.",
        "No controlled experiment or predicted savings is produced by this report.",
    ]
}

#[test]
fn policy_schema_and_unknown_fields_are_strict() {
    let e = evidence();
    code(
        OpportunityCollector::new(&e, Some(&OpportunityPolicy::default()), MEMORY).map(|_| ()),
        "opportunities.policy",
    );
    let valid: OpportunityPolicy =
        serde_json::from_value(json!({"schema": POLICY_SCHEMA})).unwrap();
    validate_policy(&valid).unwrap();
    for schema in [
        "",
        "vitnet.opportunity-policy.v0",
        "vitnet.opportunity-policy.v2",
        "vitnet.opportunities.v1",
    ] {
        code(
            validate_policy(&OpportunityPolicy {
                schema: schema.into(),
                ..policy()
            }),
            "opportunities.policy",
        );
    }
    code(
        validate_policy(&OpportunityPolicy::default()),
        "opportunities.policy",
    );
    assert!(
        serde_json::from_value::<OpportunityPolicy>(json!({"schema": POLICY_SCHEMA, "unknown": 1}))
            .unwrap_err()
            .to_string()
            .contains("unknown field")
    );
    for mut value in [
        serde_json::to_value(rule("custom", &["x"], &[])).unwrap(),
        serde_json::to_value(capability("custom", &["A", "B"])).unwrap(),
    ] {
        value["unknown"] = json!(1);
        let failure = if value.get("kind").is_some() {
            serde_json::from_value::<PatternRule>(value).unwrap_err()
        } else {
            serde_json::from_value::<CapabilityRule>(value).unwrap_err()
        };
        assert!(failure.to_string().contains("unknown field"));
    }
    assert!(
        serde_json::from_value::<OpportunityPolicy>(json!({}))
            .unwrap_err()
            .to_string()
            .contains("schema")
    );
}

#[test]
fn policy_rule_limits_use_bytes_and_exact_boundaries() {
    for count in [63, 64, 65] {
        for split in [0, count / 2, count] {
            let p = OpportunityPolicy {
                rules: (0..split)
                    .map(|n| rule(&format!("r{n}"), &["x"], &[]))
                    .collect(),
                capabilities: (split..count)
                    .map(|n| capability(&format!("c{n}"), &["A", "B"]))
                    .collect(),
                ..policy()
            };
            if count <= 64 {
                validate_policy(&p).unwrap();
            } else {
                code(validate_policy(&p), "resource.opportunities.policy");
            }
        }
    }
}

#[test]
fn policy_text_and_selector_limits_use_exact_byte_boundaries() {
    for (field, max) in [("id", 128), ("title", 1024), ("investigation", 4096)] {
        for n in [max - 1, max, max + 1] {
            for multibyte in [false, true] {
                let text = if multibyte {
                    format!("{}{}", "é".repeat(n / 2), "x".repeat(n % 2))
                } else {
                    "x".repeat(n)
                };
                assert_eq!(text.len(), n);
                let mut p = policy();
                let mut r = rule("custom", &["x"], &[]);
                match field {
                    "id" => r.id = text,
                    "title" => r.title = text,
                    _ => r.investigation = text,
                }
                p.rules.push(r);
                if n <= max {
                    validate_policy(&p).unwrap();
                } else {
                    code(validate_policy(&p), "opportunities.policy");
                }
                let mut p = policy();
                let mut c = capability("custom", &["A", "B"]);
                let text = "x".repeat(n);
                match field {
                    "id" => c.id = text,
                    "title" => c.title = text,
                    _ => c.investigation = text,
                }
                p.capabilities.push(c);
                if n <= max {
                    validate_policy(&p).unwrap();
                } else {
                    code(validate_policy(&p), "opportunities.policy");
                }
            }
        }
    }
    for count in [63, 64, 65] {
        for selector in ["contains", "assemblies", "capability"] {
            let terms: Vec<String> = (0..count).map(|n| format!("term{n}")).collect();
            let mut p = policy();
            if selector == "capability" {
                p.capabilities.push(CapabilityRule {
                    assemblies: terms,
                    ..capability("custom", &["A", "B"])
                });
            } else {
                let mut r = rule("custom", &["x"], &[]);
                if selector == "contains" {
                    r.contains = terms;
                } else {
                    r.assemblies = terms;
                }
                p.rules.push(r);
            }
            if count <= 64 {
                validate_policy(&p).unwrap();
            } else {
                code(validate_policy(&p), "opportunities.policy");
            }
        }
    }
    for n in [0, 1, 1023, 1024, 1025] {
        for selector in ["contains", "assemblies", "capability"] {
            let text = format!("{}{}", "界".repeat(n / 3), "x".repeat(n % 3));
            assert_eq!(text.len(), n);
            let mut p = policy();
            if selector == "capability" {
                p.capabilities.push(CapabilityRule {
                    assemblies: vec![text, "other".into()],
                    ..capability("custom", &["A", "B"])
                });
            } else {
                let mut r = rule("custom", &["x"], &[]);
                if selector == "contains" {
                    r.contains = vec![text];
                } else {
                    r.assemblies = vec![text];
                }
                p.rules.push(r);
            }
            if (1..=1024).contains(&n) {
                validate_policy(&p).unwrap();
            } else {
                code(validate_policy(&p), "opportunities.policy");
            }
        }
    }
}

#[test]
fn policy_ids_selectors_and_kinds_validate_without_trimming() {
    for kind in ["generated_pattern", "generic_pattern", "unexpected_feature"] {
        for (terms, assemblies) in [(vec!["x"], vec![]), (vec![], vec!["A"])] {
            let mut r = rule("custom", &terms, &assemblies);
            r.kind = kind.into();
            validate_policy(&OpportunityPolicy {
                rules: vec![r],
                ..policy()
            })
            .unwrap();
        }
    }
    for field in ["id", "title", "investigation", "kind", "selectors"] {
        let mut r = rule("custom", &["x"], &[]);
        match field {
            "id" => r.id.clear(),
            "title" => r.title.clear(),
            "investigation" => r.investigation.clear(),
            "kind" => r.kind = "removable".into(),
            _ => r.contains.clear(),
        }
        code(
            validate_policy(&OpportunityPolicy {
                rules: vec![r],
                ..policy()
            }),
            "opportunities.policy",
        );
    }
    for field in ["id", "title", "investigation"] {
        let mut c = capability("custom", &["A", "B"]);
        match field {
            "id" => c.id.clear(),
            "title" => c.title.clear(),
            _ => c.investigation.clear(),
        }
        code(
            validate_policy(&OpportunityPolicy {
                capabilities: vec![c],
                ..policy()
            }),
            "opportunities.policy",
        );
    }
    for assemblies in [vec![], vec!["A"], vec!["A", "A"], vec!["A", "B", "A"]] {
        code(
            validate_policy(&OpportunityPolicy {
                capabilities: vec![capability("c", &assemblies)],
                ..policy()
            }),
            "opportunities.policy",
        );
    }
}

#[test]
fn policy_duplicate_and_builtin_ids_are_rejected_without_trimming() {
    for p in [
        OpportunityPolicy {
            rules: vec![
                rule("duplicate", &["x"], &[]),
                rule("duplicate", &["y"], &[]),
            ],
            ..policy()
        },
        OpportunityPolicy {
            capabilities: vec![
                capability("duplicate", &["A", "B"]),
                capability("duplicate", &["C", "D"]),
            ],
            ..policy()
        },
        OpportunityPolicy {
            rules: vec![rule("duplicate", &["x"], &[])],
            capabilities: vec![capability("duplicate", &["A", "B"])],
            ..policy()
        },
    ] {
        code(validate_policy(&p), "opportunities.policy");
    }
    for id in [
        "compiled-xaml",
        "serializer-contexts",
        "async-machinery",
        "generated-code",
        "tooling-demo",
    ] {
        code(
            validate_policy(&OpportunityPolicy {
                rules: vec![rule(id, &["x"], &[])],
                ..policy()
            }),
            "opportunities.policy",
        );
        code(
            validate_policy(&OpportunityPolicy {
                capabilities: vec![capability(id, &["A", "B"])],
                ..policy()
            }),
            "opportunities.policy",
        );
    }
    let r = PatternRule {
        id: " ".into(),
        title: "\t".into(),
        investigation: "\n".into(),
        contains: vec![" ".into()],
        ..rule("x", &["x"], &[])
    };
    validate_policy(&OpportunityPolicy {
        rules: vec![r],
        capabilities: vec![capability(" c ", &[" A ", " B "])],
        ..policy()
    })
    .unwrap();
}

#[test]
fn collector_empty_and_singleton_reports_have_exact_ledgers() {
    let e = evidence();
    let p = policy();
    for configured in [None, Some(&p)] {
        let empty = collect(&e, configured, &[]);
        assert_eq!(empty.schema, "vitnet.opportunities.v1");
        assert_eq!(
            (
                empty.accounted_bytes,
                empty.source_declarations,
                empty.generated_declarations,
                empty.generator_descriptors,
                empty.malformed_shape_identities
            ),
            (0, 0, 0, 0, 0)
        );
        assert!(
            empty.streams.is_empty()
                && empty.budgets.is_empty()
                && empty.opportunities.is_empty()
                && empty.attribute_occurrences.is_empty()
        );
        assert_eq!(empty.limitations, expected_limitations());
        let single = collect(
            &e,
            configured,
            &[(
                row("Methods", "ordinary", 7, true),
                association("asserted", &["A"]),
                41,
            )],
        );
        assert_eq!(single.accounted_bytes, 7);
        assert_eq!(single.streams, streams(&[("Methods", 7)]));
        assert!(single.opportunities.is_empty());
        assert_eq!(single.budgets.len(), 2);
        for b in &single.budgets {
            assert_eq!(
                (b.additive_bytes, b.overlapping_bytes, b.identities),
                (7, 0, 1)
            );
            assert_eq!(b.streams, streams(&[("Methods", 7)]));
        }
        assert_eq!(
            budget(&single, "assembly", "A", "", "asserted").packages,
            Vec::<String>::new()
        );
        assert_eq!(
            budget(
                &single,
                "package",
                "_unmapped_package_origin",
                "",
                "asserted"
            )
            .packages,
            Vec::<String>::new()
        );
    }
}

#[test]
fn additive_and_specialized_streams_do_not_double_count() {
    let input = evidence();
    let configured_policy = OpportunityPolicy {
        rules: vec![rule("cohort", &["same"], &[])],
        ..policy()
    };
    let mut collector =
        OpportunityCollector::new(&input, Some(&configured_policy), MEMORY).unwrap();
    for (stream, bytes, additive) in [
        ("Methods", 5, true),
        ("Blobs", 7, true),
        ("ManifestResources", 11, false),
        ("FrozenObjects", 0, false),
    ] {
        collector
            .observe(
                &row(stream, "same", bytes, additive),
                &association("asserted", &["A"]),
                1,
            )
            .unwrap();
    }
    collector.observe_metadata_budget("A", 13).unwrap();
    collector
        .observe_metadata_budget("_unowned_or_omitted_metadata", 17)
        .unwrap();
    let report = collector.finish().unwrap();
    assert_eq!(report.accounted_bytes, 12);
    assert_eq!(report.streams, streams(&[("Methods", 5), ("Blobs", 7)]));
    let assembly_budget = budget(&report, "assembly", "A", "", "asserted");
    assert_eq!(
        (
            assembly_budget.additive_bytes,
            assembly_budget.overlapping_bytes,
            assembly_budget.identities
        ),
        (12, 11, 4)
    );
    assert_eq!(
        assembly_budget.streams,
        streams(&[
            ("Methods", 5),
            ("Blobs", 7),
            ("ManifestResources", 11),
            ("FrozenObjects", 0)
        ])
    );
    let cohort = finding(&report, "cohort");
    assert_eq!(
        (
            cohort.additive_bytes,
            cohort.overlapping_bytes,
            cohort.identities
        ),
        (12, 11, 4)
    );
    assert_eq!(cohort.streams, assembly_budget.streams);
    assert_eq!(cohort.proposed_savings_bytes, None);
    for (name, tier, bytes) in [
        ("A", "metadata_record_ownership_lower_bound", 13),
        (
            "_unowned_or_omitted_metadata",
            "metadata_unowned_or_omitted",
            17,
        ),
    ] {
        for (dimension, bucket) in [("assembly", name), ("package", "_unmapped_package_origin")] {
            let projection = budget(&report, dimension, bucket, "", tier);
            assert_eq!(
                (
                    projection.additive_bytes,
                    projection.overlapping_bytes,
                    projection.identities
                ),
                (0, bytes, 0)
            );
            assert_eq!(
                projection.streams,
                streams(&[("metadata_lower_bound", bytes)])
            );
            assert_eq!(projection.packages, Vec::<String>::new());
        }
    }
    assert_eq!(report.opportunities.len(), 1);
    assert_eq!(cohort.examples.len(), 3);
    assert!(
        cohort
            .examples
            .iter()
            .all(|example| example.stream != "metadata_lower_bound")
    );
}

#[test]
fn metadata_projections_preserve_tiers_and_exact_target_package_origins() {
    let mut input = evidence();
    input.mappings = vec![
        origin("A", "P1/1", "compile", "net8"),
        origin("A", "P1/1", "runtime", "net8"),
        origin("A", "P2/1", "runtime", "net8"),
        origin("A", "P2/1", "compile", "net9"),
        origin("B", "Unscoped/1", "compile", ""),
    ];
    input.packages.push(Package {
        target: "inventory-only".into(),
        id: "Inventory".into(),
        version: "1".into(),
        ..Package::default()
    });
    let configured_policy = OpportunityPolicy {
        rules: vec![rule("all-A", &[], &["A"])],
        capabilities: vec![capability("two-owners", &["A", "B"])],
        ..policy()
    };
    let mut collector =
        OpportunityCollector::new(&input, Some(&configured_policy), MEMORY).unwrap();
    for (assembly, bytes) in [("A", 13), ("B", 7), ("_unowned_or_omitted_metadata", 17)] {
        collector.observe_metadata_budget(assembly, bytes).unwrap();
    }
    let report = collector.finish().unwrap();
    assert_eq!(report.accounted_bytes, 0);
    assert_eq!(report.streams, BTreeMap::<String, u64>::new());
    assert_eq!(
        report.opportunities.len(),
        0,
        "metadata must not create examples, cohorts or implementations"
    );
    assert_package_reconciliation(
        &report,
        &["net8", "net9", "inventory-only"],
        0,
        37,
        &[("metadata_lower_bound", 37)],
    );
    for projection in &report.budgets {
        assert_eq!((projection.additive_bytes, projection.identities), (0, 0));
        assert_eq!(
            projection.streams,
            streams(&[("metadata_lower_bound", projection.overlapping_bytes)])
        );
        if projection.dimension == "package" && !projection.target.is_empty() {
            assert_ne!(projection.name, "Unscoped/1");
        }
    }
    let tier = "metadata_record_ownership_lower_bound";
    assert_eq!(
        budget(&report, "package", "Unscoped/1", "", tier).overlapping_bytes,
        7
    );
    let shared = budget(&report, "package", "_shared_package_origin", "net8", tier);
    assert_eq!(shared.overlapping_bytes, 13);
    assert_eq!(shared.packages, ["P1/1", "P2/1"]);
    assert_eq!(
        budget(&report, "package", "P2/1", "net9", tier).overlapping_bytes,
        13
    );
    for (target, bytes) in [("net8", 7), ("net9", 7), ("inventory-only", 20)] {
        assert_eq!(
            budget(&report, "package", "_unmapped_package_origin", target, tier).overlapping_bytes,
            bytes
        );
        assert_eq!(
            budget(
                &report,
                "package",
                "_unmapped_package_origin",
                target,
                "metadata_unowned_or_omitted"
            )
            .overlapping_bytes,
            17
        );
    }
    assert_eq!(
        budget(&report, "assembly", "A", "", tier).overlapping_bytes,
        13
    );
    assert_eq!(
        budget(&report, "assembly", "B", "", tier).overlapping_bytes,
        7
    );
}

#[test]
fn assembly_budgets_partition_complete_rows_by_tier() {
    let rows = vec![
        (
            row("Methods", "one", 5, true),
            association("asserted", &["A"]),
            8,
        ),
        (
            row("Methods", "two", 7, true),
            association("producer_prefix_candidate", &["A"]),
            9,
        ),
        (
            row("Blobs", "three", 11, true),
            association("managed_symbol_join", &["B"]),
            10,
        ),
        (
            row("Methods", "four", 13, true),
            association("ambiguous", &["A", "B"]),
            11,
        ),
        (
            row("Blobs", "five", 17, true),
            association("unmapped", &[]),
            12,
        ),
        (
            row("Methods", "zero", 0, true),
            association("asserted", &["A"]),
            13,
        ),
        (
            row("ManifestResources", "overlap", 19, false),
            association("asserted", &["A"]),
            14,
        ),
    ];
    let r = collect(&evidence(), None, &rows);
    assert_eq!(r.accounted_bytes, 53);
    let expected = [
        (
            "A",
            "asserted",
            5,
            19,
            3,
            streams(&[("Methods", 5), ("ManifestResources", 19)]),
        ),
        (
            "A",
            "producer_prefix_candidate",
            7,
            0,
            1,
            streams(&[("Methods", 7)]),
        ),
        (
            "B",
            "managed_symbol_join",
            11,
            0,
            1,
            streams(&[("Blobs", 11)]),
        ),
        (
            "_ambiguous",
            "ambiguous",
            13,
            0,
            1,
            streams(&[("Methods", 13)]),
        ),
        ("_unmapped", "unmapped", 17, 0, 1, streams(&[("Blobs", 17)])),
    ];
    assert_eq!(
        r.budgets
            .iter()
            .filter(|b| b.dimension == "assembly")
            .count(),
        expected.len()
    );
    for (name, tier, additive, overlap, identities, ledger) in expected {
        let b = budget(&r, "assembly", name, "", tier);
        assert_eq!(
            (b.additive_bytes, b.overlapping_bytes, b.identities),
            (additive, overlap, identities)
        );
        assert_eq!(b.streams, ledger);
        assert_eq!(b.packages, Vec::<String>::new());
    }
    for (stream, expected) in [("Methods", 25), ("Blobs", 28), ("ManifestResources", 19)] {
        assert_eq!(
            r.budgets
                .iter()
                .filter(|b| b.dimension == "assembly")
                .map(|b| b.streams.get(stream).copied().unwrap_or(0))
                .sum::<u64>(),
            expected
        );
    }
}

#[test]
fn package_budgets_reconcile_independently_within_each_target() {
    let mut e = evidence();
    e.mappings = vec![
        origin("A", "Pkg/1", "compile", "net8"),
        origin("B", "Pkg/2", "runtime", "net8"),
        origin("A", "Pkg/2", "runtime", "net9"),
        origin("B", "Pkg/1", "compile", "net9"),
    ];
    e.packages.push(Package {
        target: "inventory-only".into(),
        id: "Only".into(),
        version: "1".into(),
        ..Package::default()
    });
    let r = collect(
        &e,
        None,
        &[
            (
                row("Methods", "a", 5, true),
                association("asserted", &["A"]),
                0,
            ),
            (
                row("Blobs", "b", 7, true),
                association("candidate", &["B"]),
                1,
            ),
            (
                row("ManifestResources", "a", 11, false),
                association("asserted", &["A"]),
                2,
            ),
        ],
    );
    let expected = [
        (
            "net8",
            "Pkg/1",
            "asserted",
            5,
            11,
            streams(&[("Methods", 5), ("ManifestResources", 11)]),
        ),
        ("net8", "Pkg/2", "candidate", 7, 0, streams(&[("Blobs", 7)])),
        (
            "net9",
            "Pkg/2",
            "asserted",
            5,
            11,
            streams(&[("Methods", 5), ("ManifestResources", 11)]),
        ),
        ("net9", "Pkg/1", "candidate", 7, 0, streams(&[("Blobs", 7)])),
        (
            "inventory-only",
            "_unmapped_package_origin",
            "asserted",
            5,
            11,
            streams(&[("Methods", 5), ("ManifestResources", 11)]),
        ),
        (
            "inventory-only",
            "_unmapped_package_origin",
            "candidate",
            7,
            0,
            streams(&[("Blobs", 7)]),
        ),
    ];
    assert_eq!(
        r.budgets
            .iter()
            .filter(|b| b.dimension == "package")
            .count(),
        6
    );
    for (target, name, tier, additive, overlapping, ledger) in expected {
        let b = budget(&r, "package", name, target, tier);
        assert_eq!(
            (b.additive_bytes, b.overlapping_bytes, b.identities),
            (
                additive,
                overlapping,
                if tier == "asserted" { 2 } else { 1 }
            )
        );
        assert_eq!(b.streams, ledger);
        assert_budget_origin_candidates(b, name);
    }
    assert_package_reconciliation(
        &r,
        &["net8", "net9", "inventory-only"],
        12,
        11,
        &[("Methods", 5), ("Blobs", 7), ("ManifestResources", 11)],
    );
}

fn assert_budget_origin_candidates(budget: &Budget, name: &str) {
    assert_eq!(
        budget.packages,
        if name.starts_with('_') {
            vec![]
        } else {
            vec![name.to_owned()]
        }
    );
}

fn assert_package_reconciliation(
    report: &OpportunityReport,
    targets: &[&str],
    additive: u64,
    overlapping: u64,
    stream_bytes: &[(&str, u64)],
) {
    for target in targets {
        let rows: Vec<_> = report
            .budgets
            .iter()
            .filter(|b| b.dimension == "package" && b.target == *target)
            .collect();
        assert_eq!(rows.iter().map(|b| b.additive_bytes).sum::<u64>(), additive);
        assert_eq!(
            rows.iter().map(|b| b.overlapping_bytes).sum::<u64>(),
            overlapping
        );
        for (stream, expected) in stream_bytes {
            assert_eq!(
                rows.iter()
                    .map(|b| b.streams.get(*stream).copied().unwrap_or(0))
                    .sum::<u64>(),
                *expected
            );
        }
    }
}

#[test]
fn shared_package_origins_deduplicate_roles_without_multiplying_bytes() {
    for shared in [false, true] {
        let mut e = evidence();
        e.mappings = vec![
            origin("A", "Z/1", "compile", "net8"),
            origin("A", "Z/1", "runtime", "net8"),
        ];
        if shared {
            e.mappings.push(origin("A", "A/2", "runtime", "net8"));
        }
        let entries = [(
            row("Methods", "a", 23, true),
            association("asserted", &["A"]),
            0,
        )];
        let forward = collect(&e, None, &entries);
        e.mappings.reverse();
        let reverse = collect(&e, None, &entries);
        assert_eq!(
            serde_json::to_value(&forward).unwrap(),
            serde_json::to_value(&reverse).unwrap()
        );
        assert_eq!(forward.accounted_bytes, 23);
        let b = budget(
            &forward,
            "package",
            if shared {
                "_shared_package_origin"
            } else {
                "Z/1"
            },
            "net8",
            "asserted",
        );
        assert_eq!(
            (b.additive_bytes, b.overlapping_bytes, b.identities),
            (23, 0, 1)
        );
        assert_eq!(b.streams, streams(&[("Methods", 23)]));
        assert_eq!(
            b.packages,
            if shared {
                vec!["A/2", "Z/1"]
            } else {
                vec!["Z/1"]
            }
        );
        assert_eq!(
            forward
                .budgets
                .iter()
                .filter(|b| b.dimension == "package")
                .count(),
            1
        );
    }
}

#[test]
fn package_unknown_ambiguous_and_legacy_targets_stay_distinct() {
    let mut e = evidence();
    e.assemblies.push(Assembly {
        name: "A".into(),
        package: Some("Legacy/1".into()),
        ..Assembly::default()
    });
    let legacy = collect(
        &e,
        None,
        &[(
            row("Methods", "a", 5, true),
            association("asserted", &["A"]),
            0,
        )],
    );
    assert_eq!(
        budget(&legacy, "package", "Legacy/1", "", "asserted").additive_bytes,
        5
    );
    let empty = collect(
        &evidence(),
        None,
        &[(
            row("Methods", "a", 7, true),
            association("unmapped", &[]),
            0,
        )],
    );
    assert_eq!(
        budget(
            &empty,
            "package",
            "_unmapped_package_origin",
            "",
            "unmapped"
        )
        .additive_bytes,
        7
    );
}

#[test]
fn named_targets_never_inherit_unscoped_package_origins() {
    let mut e = evidence();
    e.assemblies.push(Assembly {
        name: "A".into(),
        package: Some("Legacy/1".into()),
        ..Assembly::default()
    });
    e.mappings = vec![
        origin("A", "Explicit/2", "compile", "net8"),
        origin("B", "B/1", "runtime", "net8"),
    ];
    e.packages.push(Package {
        target: "net9".into(),
        id: "Inventory".into(),
        version: "1".into(),
        ..Package::default()
    });
    let r = collect(
        &e,
        None,
        &[
            (
                row("Methods", "known", 5, true),
                association("asserted", &["A"]),
                0,
            ),
            (
                row("Methods", "unknown", 7, true),
                association("candidate", &["Unknown"]),
                1,
            ),
            (
                row("Blobs", "ambiguous", 11, true),
                association("ambiguous", &["A", "B"]),
                2,
            ),
        ],
    );
    assert_eq!(
        budget(&r, "package", "Explicit/2", "net8", "asserted").packages,
        ["Explicit/2"]
    );
    for target in ["net8", "net9"] {
        assert_eq!(
            budget(
                &r,
                "package",
                "_unmapped_package_origin",
                target,
                "candidate"
            )
            .additive_bytes,
            7
        );
        assert_eq!(
            budget(
                &r,
                "package",
                "_unmapped_package_origin",
                target,
                "ambiguous"
            )
            .additive_bytes,
            11
        );
        assert!(
            !r.budgets
                .iter()
                .any(|b| b.dimension == "package" && b.target == target && b.name == "B/1")
        );
    }
    // A target-empty legacy assertion is not an origin assertion for net9.
    assert_eq!(
        budget(
            &r,
            "package",
            "_unmapped_package_origin",
            "net9",
            "asserted"
        )
        .additive_bytes,
        5
    );
    assert!(!r.budgets.iter().any(|b| b.dimension == "package"
        && b.target == "net9"
        && b.packages.contains(&"Legacy/1".into())));
}

#[test]
fn literal_pattern_selectors_use_or_within_and_between_groups() {
    let p = OpportunityPolicy {
        rules: vec![
            rule("both", &["alpha", "beta"], &["A", "B"]),
            rule("literal", &["a.*[b]"], &[]),
            rule("assembly-only", &[], &["Exact"]),
            rule("name-only", &["only"], &[]),
        ],
        ..policy()
    };
    let cases = [
        ("alpha", vec!["A"], 2, vec!["both"]),
        ("prefix-beta-suffix", vec!["B"], 3, vec!["both"]),
        ("alpha", vec!["B", "Other"], 5, vec!["both"]),
        ("alpha", vec!["Other"], 7, vec![]),
        ("ordinary", vec!["A"], 11, vec![]),
        ("ordinary", vec!["Other"], 13, vec![]),
        ("ALPHA", vec!["A"], 17, vec![]),
        ("alpha", vec!["a"], 19, vec![]),
        ("a.*[b]", vec![], 23, vec!["literal"]),
        ("prefix-a.*[b]-end", vec![], 29, vec!["literal"]),
        ("axxxb", vec![], 31, vec![]),
        ("a.*[c]", vec![], 37, vec![]),
        ("ordinary", vec!["Exact"], 41, vec!["assembly-only"]),
        ("ordinary", vec!["ExactSuffix"], 43, vec![]),
        ("only", vec![], 47, vec!["name-only"]),
    ];
    for (name, assemblies, bytes, ids) in &cases {
        let r = collect(
            &evidence(),
            Some(&p),
            &[(
                row("Methods", name, *bytes, true),
                association("candidate", assemblies),
                81,
            )],
        );
        assert_eq!(r.accounted_bytes, *bytes);
        assert_eq!(
            r.opportunities
                .iter()
                .map(|f| f.id.as_str())
                .collect::<Vec<_>>(),
            *ids,
            "{name}/{assemblies:?}"
        );
        for f in &r.opportunities {
            assert_eq!(
                (f.additive_bytes, f.overlapping_bytes, f.identities),
                (*bytes, 0, 1)
            );
            assert_eq!(f.streams, streams(&[("Methods", *bytes)]));
        }
    }
    let entries: Vec<_> = cases
        .iter()
        .enumerate()
        .map(|(n, (name, assemblies, bytes, _))| {
            (
                row("Methods", name, *bytes, true),
                association("candidate", assemblies),
                n as u64,
            )
        })
        .collect();
    let r = collect(&evidence(), Some(&p), &entries);
    for (id, bytes, identities) in [
        ("both", 10, 3),
        ("literal", 52, 2),
        ("assembly-only", 41, 1),
        ("name-only", 47, 1),
    ] {
        let f = finding(&r, id);
        assert_eq!((f.additive_bytes, f.identities), (bytes, identities));
    }
}

#[test]
fn overlapping_rules_preserve_one_global_charge_and_null_savings() {
    let p = OpportunityPolicy {
        rules: vec![
            rule("one", &["match"], &[]),
            rule("two", &["match"], &["A"]),
        ],
        ..policy()
    };
    for (assemblies, expected_ids) in [(vec!["B"], vec!["one"]), (vec!["A"], vec!["one", "two"])] {
        let single = collect(
            &evidence(),
            Some(&p),
            &[(
                row("Methods", "match", 13, true),
                association("asserted", &assemblies),
                42,
            )],
        );
        assert_eq!(single.accounted_bytes, 13);
        assert_eq!(
            single
                .opportunities
                .iter()
                .map(|f| f.id.as_str())
                .collect::<Vec<_>>(),
            expected_ids
        );
        for f in &single.opportunities {
            assert_eq!(
                (f.additive_bytes, f.overlapping_bytes, f.identities),
                (13, 0, 1)
            );
            assert_eq!(f.proposed_savings_bytes, None);
            assert_eq!(
                serde_json::to_value(f).unwrap()["proposed_savings_bytes"],
                Value::Null
            );
        }
        let r = collect(
            &evidence(),
            Some(&p),
            &[
                (
                    row("Methods", "match", 13, true),
                    association("asserted", &assemblies),
                    42,
                ),
                (
                    row("ManifestResources", "match", 7, false),
                    association("asserted", &assemblies),
                    43,
                ),
            ],
        );
        assert_eq!(r.accounted_bytes, 13);
        assert_eq!(r.streams, streams(&[("Methods", 13)]));
        assert_eq!(
            r.opportunities
                .iter()
                .map(|f| f.id.as_str())
                .collect::<Vec<_>>(),
            expected_ids
        );
        for f in &r.opportunities {
            assert_eq!(
                (f.additive_bytes, f.overlapping_bytes, f.identities),
                (13, 7, 2)
            );
            assert_eq!(
                f.streams,
                streams(&[("Methods", 13), ("ManifestResources", 7)])
            );
            assert_eq!(f.proposed_savings_bytes, None);
            assert_eq!(
                serde_json::to_value(f).unwrap()["proposed_savings_bytes"],
                Value::Null
            );
        }
        assert_eq!(
            r.opportunities
                .iter()
                .map(|f| f.additive_bytes)
                .sum::<u64>(),
            13 * expected_ids.len() as u64
        );
        assert!(r.limitations.iter().any(|s| s == expected_limitations()[0]));
    }
}

#[test]
fn default_name_rules_are_generic_and_application_neutral() {
    for (id, kind, names) in [
        (
            "compiled-xaml",
            "generated_pattern",
            vec!["XamlIl", "XamlClosure", "CompiledAvaloniaXaml"],
        ),
        (
            "serializer-contexts",
            "generated_pattern",
            vec!["JsonSerializerContext", "JsonContext"],
        ),
        (
            "async-machinery",
            "generic_pattern",
            vec!["AsyncStateMachineBox", "AsyncTaskMethodBuilder"],
        ),
        (
            "generated-code",
            "generated_pattern",
            vec!["Internal_CompilerGenerated"],
        ),
        (
            "tooling-demo",
            "unexpected_feature",
            vec![
                "DevTools",
                "UIDemos",
                "DemoView",
                "_Tests_",
                "_Benchmarks_",
                "_Samples_",
            ],
        ),
    ] {
        for name in names {
            let r = collect(
                &evidence(),
                None,
                &[(
                    row("Methods", &format!("AnyApp_{name}__Run"), 17, true),
                    association("candidate", &["AnyApp"]),
                    7,
                )],
            );
            assert_eq!(r.opportunities.len(), 1, "{name}");
            let f = finding(&r, id);
            assert_eq!(f.kind, kind);
            assert_eq!((f.additive_bytes, f.identities), (17, 1));
            assert_eq!(f.evidence_tier, "producer_name_candidate");
            assert_eq!(f.proposed_savings_bytes, None);
            assert!(f.basis.contains("not verified generator ownership"));
        }
    }
    for name in [
        "XamIl",
        "xamlil",
        "JsonSerializContext",
        "jsoncontext",
        "AsyncTaskBuilder",
        "Internal_CompilerGenerate",
        "DevTool",
        "_tests_",
        "RDM_Application__Run",
        "RemoteDesktopManager__Run",
        "ArbitraryShippingApp__Run",
    ] {
        let r = collect(
            &evidence(),
            None,
            &[(
                row("Methods", name, 19, true),
                association("candidate", &["Application"]),
                1,
            )],
        );
        assert!(r.opportunities.is_empty(), "{name}");
        assert_eq!(r.accounted_bytes, 19);
    }
}

#[test]
fn generic_families_are_stream_scoped_and_suppress_only_singletons() {
    let e = evidence();
    let p = OpportunityPolicy {
        rules: vec![rule("singleton-rule", &["Solo"], &[])],
        ..policy()
    };
    let singleton = collect(
        &e,
        Some(&p),
        &[(
            row("Methods", "Solo<X>", 5, true),
            association("unmapped", &[]),
            3,
        )],
    );
    assert_eq!(
        singleton
            .opportunities
            .iter()
            .map(|f| f.id.as_str())
            .collect::<Vec<_>>(),
        ["singleton-rule"]
    );
    assert_eq!(finding(&singleton, "singleton-rule").identities, 1);
    assert_generic_stream_separation(&e);
}

#[test]
fn generic_zero_and_overlapping_families_keep_stream_and_identity_counts() {
    let e = evidence();
    for additive in [true, false] {
        let r = collect(
            &e,
            None,
            &[
                (
                    row("Types", "Zero<A>", 0, additive),
                    association("unmapped", &[]),
                    0,
                ),
                (
                    row("Types", "Zero<B>", 0, additive),
                    association("unmapped", &[]),
                    1,
                ),
            ],
        );
        let f = finding(&r, "family:Types:Zero<>");
        assert_eq!(
            (f.identities, f.additive_bytes, f.overlapping_bytes),
            (2, 0, 0)
        );
        assert_eq!(f.streams, streams(&[("Types", 0)]));
        assert_eq!(r.accounted_bytes, 0);
        let r = collect(
            &e,
            None,
            &[
                (
                    row("Types", "Overlap<A>", 3, additive),
                    association("unmapped", &[]),
                    0,
                ),
                (
                    row("Types", "Overlap<B>", 5, additive),
                    association("unmapped", &[]),
                    1,
                ),
            ],
        );
        let f = finding(&r, "family:Types:Overlap<>");
        assert_eq!(
            (f.identities, f.additive_bytes, f.overlapping_bytes),
            (
                2,
                if additive { 8 } else { 0 },
                if additive { 0 } else { 8 }
            )
        );
        assert_eq!(r.accounted_bytes, if additive { 8 } else { 0 });
    }
}

fn assert_generic_stream_separation(e: &Evidence) {
    let r = collect(
        e,
        None,
        &[
            (
                row("Methods", "Family<A>", 3, true),
                association("unmapped", &[]),
                0,
            ),
            (
                row("Methods", "Family<B>", 5, true),
                association("unmapped", &[]),
                1,
            ),
            (
                row("Types", "Family<C>", 7, true),
                association("unmapped", &[]),
                2,
            ),
            (
                row("Types", "Family<D>", 11, true),
                association("unmapped", &[]),
                3,
            ),
            (
                row("Blobs", "Family<E>", 13, true),
                association("unmapped", &[]),
                4,
            ),
            (
                row("Methods", "Plain", 17, true),
                association("unmapped", &[]),
                5,
            ),
            (
                row("Methods", "Solo<X>", 19, true),
                association("unmapped", &[]),
                6,
            ),
        ],
    );
    assert_eq!(r.accounted_bytes, 75);
    assert_eq!(r.opportunities.len(), 2);
    for (stream, bytes) in [("Methods", 8), ("Types", 18)] {
        let f = finding(&r, &format!("family:{stream}:Family<>"));
        assert_eq!(f.family.as_deref(), Some("Family<>"));
        assert_eq!(
            (
                f.identities,
                f.additive_bytes,
                f.canonical_shared_identities
            ),
            (2, bytes, 0)
        );
        assert_eq!(f.streams, streams(&[(stream, bytes)]));
        assert_eq!(f.evidence_tier, "parsed_producer_family");
    }
}

#[test]
fn generic_canonical_counts_track_identities_not_raw_records() {
    let cases = [
        ("Outer<Inner<A>,B>__Run<C>", "Outer<>__Run<>", 3),
        (
            "Outer<Inner<__Canon>__D>__Run<___Canon>",
            "Outer<>__Run<>",
            5,
        ),
        ("Outer<X,Y>__Run<Z>", "Outer<>__Run<>", 7),
        ("Pair<A__B>", "Pair<>", 11),
        ("Pair<__Canon,Other>", "Pair<>", 13),
        ("Pair<___Canon__Other>", "Pair<>", 17),
    ];
    let entries: Vec<_> = cases
        .iter()
        .enumerate()
        .map(|(n, (name, _, bytes))| {
            let mut entry = row("Methods", name, *bytes, true);
            entry.records = 1000 + n as u64;
            (entry, association("candidate", &["A"]), n as u64)
        })
        .collect();
    let r = collect(&evidence(), None, &entries);
    assert_eq!(r.accounted_bytes, 56);
    assert_eq!(r.opportunities.len(), 2);
    for (family, bytes, canon) in [("Outer<>__Run<>", 15, 1), ("Pair<>", 41, 2)] {
        let f = finding(&r, &format!("family:Methods:{family}"));
        assert_eq!(
            (
                f.identities,
                f.additive_bytes,
                f.canonical_shared_identities
            ),
            (3, bytes, canon)
        );
        assert_eq!(f.family.as_deref(), Some(family));
        assert_eq!(f.proposed_savings_bytes, None);
        assert!(f.basis.contains("not source-language instantiation count"));
    }
}

#[test]
fn malformed_and_lossy_shapes_keep_bytes_without_fabricating_findings() {
    let deep = format!("Deep{}A{}", "<".repeat(65), ">".repeat(65));
    let oversized = format!("TooBig<{}>", "x".repeat(usize::try_from(MIB).unwrap()));
    let malformed = [
        "Broken<",
        "Empty<>",
        "Extra<A>>",
        "Pair<A,,B>",
        &deep,
        &oversized,
    ];
    let mut entries = vec![
        (
            row("Methods", "Good<A>", 2, true),
            association("asserted", &["A"]),
            0,
        ),
        (
            row("Methods", "Good<B>", 3, true),
            association("asserted", &["A"]),
            1,
        ),
        (
            row("Methods", "Plain", 5, true),
            association("asserted", &["A"]),
            2,
        ),
        (
            row("Blobs", "Unsupported<A>", 7, true),
            association("asserted", &["A"]),
            3,
        ),
        (
            row("Blobs", "Bad<", 11, true),
            association("asserted", &["A"]),
            4,
        ),
    ];
    for (n, name) in malformed.iter().enumerate() {
        entries.push((
            row("Methods", name, 13, true),
            association("asserted", &["A"]),
            10 + n as u64,
        ));
    }
    for name in ["Good<__Canon>", "XamlIl_Broken<"] {
        let mut entry = row("Methods", name, 17, true);
        entry.identity_lossy = true;
        let mut sources = association("unmapped_lossy_identity", &[]);
        sources
            .sources
            .push(source("Captured", Some("Emitter"), &[]));
        entries.push((entry, sources, 30));
    }
    let r = collect(&evidence(), None, &entries);
    assert_eq!(r.accounted_bytes, 140);
    assert_eq!(r.malformed_shape_identities, 6);
    assert_eq!(r.opportunities.len(), 1);
    let f = finding(&r, "family:Methods:Good<>");
    assert_eq!(
        (
            f.additive_bytes,
            f.identities,
            f.canonical_shared_identities
        ),
        (5, 2, 0)
    );
    assert_eq!(
        budget(&r, "assembly", "A", "", "asserted").additive_bytes,
        106
    );
    assert_eq!(
        budget(&r, "assembly", "_unmapped", "", "unmapped_lossy_identity").additive_bytes,
        34
    );
    assert_eq!(r.streams, streams(&[("Methods", 122), ("Blobs", 18)]));
}

#[test]
fn finding_and_budget_ranks_are_deterministic_on_equal_bytes() {
    let p = OpportunityPolicy {
        rules: vec![
            rule("z-rule", &["z"], &[]),
            rule("a-rule", &["a"], &[]),
            rule("big-rule", &["BIG"], &[]),
            rule("zero-rule", &["ZERO"], &[]),
        ],
        ..policy()
    };
    let mut e = evidence();
    e.mappings = vec![
        origin("A", "PA", "compile", "t2"),
        origin("A", "PA", "compile", "t1"),
        origin("B", "PB", "runtime", "t2"),
        origin("B", "PB", "runtime", "t1"),
    ];
    let mut rows = vec![
        (
            row("Methods", "z", 10, true),
            association("z-tier", &["B"]),
            9,
        ),
        (
            row("Methods", "a", 10, true),
            association("b-tier", &["A"]),
            7,
        ),
        (
            row("Methods", "a", 0, true),
            association("a-tier", &["A"]),
            5,
        ),
        (
            row("Methods", "BIG", 11, true),
            association("asserted", &["C"]),
            3,
        ),
        (
            row("ManifestResources", "ZERO", 8, false),
            association("z-tier", &["Z"]),
            1,
        ),
    ];
    let forward = collect(&e, Some(&p), &rows);
    rows.reverse();
    let reverse = collect(&e, Some(&p), &rows);
    assert_eq!(
        serde_json::to_value(&forward).unwrap(),
        serde_json::to_value(&reverse).unwrap()
    );
    assert_eq!(
        forward
            .opportunities
            .iter()
            .map(|f| (f.id.as_str(), f.additive_bytes))
            .collect::<Vec<_>>(),
        [
            ("big-rule", 11),
            ("a-rule", 10),
            ("z-rule", 10),
            ("zero-rule", 0)
        ]
    );
    let ordered: Vec<_> = forward
        .budgets
        .iter()
        .map(|b| {
            (
                b.additive_bytes,
                b.dimension.as_str(),
                b.target.as_str(),
                b.name.as_str(),
                b.evidence_tier.as_str(),
            )
        })
        .collect();
    assert_eq!(
        ordered,
        vec![
            (11, "assembly", "", "C", "asserted"),
            (11, "package", "t1", "_unmapped_package_origin", "asserted"),
            (11, "package", "t2", "_unmapped_package_origin", "asserted"),
            (10, "assembly", "", "A", "b-tier"),
            (10, "assembly", "", "B", "z-tier"),
            (10, "package", "t1", "PA", "b-tier"),
            (10, "package", "t1", "PB", "z-tier"),
            (10, "package", "t2", "PA", "b-tier"),
            (10, "package", "t2", "PB", "z-tier"),
            (0, "assembly", "", "A", "a-tier"),
            (0, "assembly", "", "Z", "z-tier"),
            (0, "package", "t1", "PA", "a-tier"),
            (0, "package", "t1", "_unmapped_package_origin", "z-tier"),
            (0, "package", "t2", "PA", "a-tier"),
            (0, "package", "t2", "_unmapped_package_origin", "z-tier"),
        ]
    );
}

#[test]
fn examples_keep_top_three_original_ordinals() {
    type ExamplePairs = Vec<(u64, u64)>;
    let p = OpportunityPolicy {
        rules: vec![rule("examples", &["sample"], &[])],
        ..policy()
    };
    let cases: Vec<(ExamplePairs, ExamplePairs)> = vec![
        (vec![], vec![]),
        (vec![(7, 99)], vec![(7, 99)]),
        (
            vec![(3, 88), (11, 44), (7, 22)],
            vec![(11, 44), (7, 22), (3, 88)],
        ),
        (
            vec![(3, 88), (11, 44), (7, 22), (2, 10), (13, 66)],
            vec![(13, 66), (11, 44), (7, 22)],
        ),
    ];
    for (inputs, expected) in cases {
        let entries: Vec<_> = inputs
            .iter()
            .map(|(bytes, ordinal)| {
                (
                    row("Methods", &format!("sample-{ordinal}"), *bytes, true),
                    association("unmapped", &[]),
                    *ordinal,
                )
            })
            .collect();
        let r = collect(&evidence(), Some(&p), &entries);
        if expected.is_empty() {
            assert!(r.opportunities.is_empty());
            continue;
        }
        let f = finding(&r, "examples");
        assert_eq!(
            f.examples
                .iter()
                .map(|e| (e.bytes, e.ordinal))
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(f.identities, inputs.len() as u64);
        for example in &f.examples {
            assert_eq!(example.identity, format!("sample-{}", example.ordinal));
            assert_eq!(example.stream, "Methods");
            assert!(!example.truncated);
        }
    }
}

#[test]
fn example_equal_byte_ties_admit_smaller_out_of_order_ordinals() {
    let p = OpportunityPolicy {
        rules: vec![rule("ties", &["sample"], &[])],
        ..policy()
    };
    let entries: Vec<_> = [9, 7, 5, 1]
        .into_iter()
        .map(|ordinal| {
            (
                row("Methods", &format!("sample-{ordinal}"), 10, true),
                association("asserted", &["A"]),
                ordinal,
            )
        })
        .collect();
    let r = collect(&evidence(), Some(&p), &entries);
    let f = finding(&r, "ties");
    assert_eq!((f.additive_bytes, f.identities), (40, 4));
    assert_eq!(
        f.examples.iter().map(|e| e.ordinal).collect::<Vec<_>>(),
        [1, 5, 7]
    );
    assert_eq!(
        f.examples
            .iter()
            .map(|e| e.identity.as_str())
            .collect::<Vec<_>>(),
        ["sample-1", "sample-5", "sample-7"]
    );
}

#[test]
fn example_previews_truncate_on_utf8_boundaries() {
    let p = OpportunityPolicy {
        rules: vec![rule("preview", &["P"], &[])],
        ..policy()
    };
    let cases = [
        (
            format!("P{}", "x".repeat(510)),
            format!("P{}", "x".repeat(510)),
            false,
        ),
        (
            format!("P{}", "x".repeat(511)),
            format!("P{}", "x".repeat(511)),
            false,
        ),
        (
            format!("P{}E", "x".repeat(511)),
            format!("P{}", "x".repeat(511)),
            true,
        ),
        (
            format!("P{}界END", "x".repeat(510)),
            format!("P{}", "x".repeat(510)),
            true,
        ),
        (
            format!("P{}éEND", "x".repeat(509)),
            format!("P{}é", "x".repeat(509)),
            true,
        ),
    ];
    for (original, preview, truncated) in cases {
        let entry = row("Methods", &original, 31, true);
        let original_hash = entry.raw_identity_blake3.clone();
        let r = collect(
            &evidence(),
            Some(&p),
            &[(entry.clone(), association("asserted", &["A"]), 901)],
        );
        let examples = &finding(&r, "preview").examples;
        assert_eq!(examples.len(), 1);
        assert_eq!(
            (
                examples[0].ordinal,
                examples[0].bytes,
                examples[0].truncated
            ),
            (901, 31, truncated)
        );
        assert_eq!(examples[0].identity, preview);
        assert!(examples[0].identity.len() <= 512);
        assert!(original.is_char_boundary(examples[0].identity.len()));
        assert_eq!(entry.identity, original);
        assert_eq!(entry.raw_identity_blake3, original_hash);
        assert_eq!(serde_json::to_value(&examples[0]).unwrap()["ordinal"], 901);
    }
}

#[test]
fn capability_threshold_counts_distinct_additive_implementations() {
    let p = OpportunityPolicy {
        capabilities: vec![capability("overlap", &["A", "B", "C"])],
        ..policy()
    };
    for count in 0..=3 {
        let names = ["A", "B", "C"];
        let sizes = [3, 5, 7];
        let mut entries = Vec::new();
        for n in 0..count {
            entries.push((
                row("Methods", &format!("implementation-{n}"), sizes[n], true),
                association("asserted", &[names[n]]),
                n as u64,
            ));
        }
        let r = collect(&evidence(), Some(&p), &entries);
        if count < 2 {
            assert!(r.opportunities.is_empty());
        } else {
            let f = finding(&r, "overlap");
            assert_eq!(f.kind, "capability_overlap");
            assert_eq!(f.evidence_tier, "policy_candidate");
            assert_eq!(f.assemblies, names[..count]);
            assert_eq!(f.investigation, "Verify behavior and registrations");
            assert_eq!(
                (f.additive_bytes, f.overlapping_bytes, f.identities),
                (if count == 2 { 8 } else { 15 }, 0, count as u64)
            );
            assert_eq!(f.proposed_savings_bytes, None);
            assert!(f.examples.is_empty() && f.selector_terms.is_empty());
        }
    }
    for second in [
        None,
        Some(("ManifestResources", 11, false)),
        Some(("Methods", 0, true)),
    ] {
        let mut entries = vec![
            (
                row("Methods", "a1", 3, true),
                association("asserted", &["A"]),
                0,
            ),
            (
                row("Blobs", "a2", 5, true),
                association("candidate", &["A"]),
                1,
            ),
        ];
        if let Some((stream, bytes, additive)) = second {
            entries.push((
                row(stream, "b", bytes, additive),
                association("asserted", &["B"]),
                2,
            ));
        }
        assert!(
            collect(&evidence(), Some(&p), &entries)
                .opportunities
                .is_empty()
        );
    }
}

#[test]
fn capability_tier_aggregation_excludes_ambiguous_and_nonexact_assemblies() {
    let p = OpportunityPolicy {
        capabilities: vec![capability("overlap", &["A", "B", "C"])],
        ..policy()
    };
    let r = collect(
        &evidence(),
        Some(&p),
        &[
            (
                row("Methods", "a1", 3, true),
                association("asserted", &["A"]),
                0,
            ),
            (
                row("Blobs", "a2", 5, true),
                association("candidate", &["A"]),
                1,
            ),
            (
                row("Methods", "b", 7, true),
                association("asserted", &["B"]),
                2,
            ),
            (
                row("ManifestResources", "b-special", 11, false),
                association("candidate", &["B"]),
                3,
            ),
            (
                row("Methods", "not-exact", 13, true),
                association("asserted", &["CSuffix"]),
                4,
            ),
            (
                row("Methods", "ambiguous", 17, true),
                association("ambiguous", &["A", "C"]),
                5,
            ),
        ],
    );
    let f = finding(&r, "overlap");
    assert_eq!(f.assemblies, ["A", "B"]);
    assert_eq!(
        (f.additive_bytes, f.overlapping_bytes, f.identities),
        (15, 11, 4)
    );
    assert_eq!(
        f.streams,
        streams(&[("Methods", 10), ("Blobs", 5), ("ManifestResources", 11)])
    );
    assert_eq!(r.accounted_bytes, 45);
}

#[test]
fn report_evidence_counts_and_limitations_preserve_occurrences() {
    let mut e = evidence();
    e.sources = vec![
        source(
            "First",
            Some("Emitter"),
            &[" Mark(1) ", "Mark(2)", "ModuleInitializer"],
        ),
        source("First", Some("Emitter"), &["Mark", "Other(x)", "Other(y)"]),
        source("Plain", None, &["Mark"]),
    ];
    e.generators = vec![
        Generator {
            name: "Emitter".into(),
            version: "1".into(),
            ..Generator::default()
        },
        Generator {
            name: "Emitter".into(),
            version: "2".into(),
            ..Generator::default()
        },
    ];
    let p = OpportunityPolicy {
        rules: vec![rule("project-policy", &["Plain"], &[])],
        ..policy()
    };
    let r = collect(&e, Some(&p), &[]);
    assert_eq!(
        (
            r.source_declarations,
            r.generated_declarations,
            r.generator_descriptors
        ),
        (3, 2, 2)
    );
    assert_eq!(
        r.attribute_occurrences,
        streams(&[("Mark", 4), ("ModuleInitializer", 1), ("Other", 2)])
    );
    assert!(r.opportunities.is_empty());
    assert_eq!(r.limitations, expected_limitations());
    let mut matched = association("asserted", &["App"]);
    matched.sources = e.sources[..2].to_vec();
    let projected = collect(
        &e,
        Some(&p),
        &[(row("Methods", "Plain", 19, true), matched, 6)],
    );
    assert_eq!(projected.accounted_bytes, 19);
    let policy_finding = finding(&projected, "project-policy");
    assert_eq!(policy_finding.selector_terms, ["Plain"]);
    assert_eq!(
        policy_finding.investigation,
        "Inspect retention; no savings claim"
    );
    let generator = finding(&projected, "generator:Emitter");
    assert_eq!((generator.additive_bytes, generator.identities), (19, 1));
    assert_eq!(
        generator.evidence_tier,
        "asserted+captured_generator_declaration"
    );
    assert!(
        generator
            .basis
            .contains("does not prove generator execution or exclusive byte ownership")
    );
    assert_eq!(generator.proposed_savings_bytes, None);
    let mut conflicting = association("candidate", &["App"]);
    conflicting.sources = vec![
        source("First", Some("Emitter"), &[]),
        source("Other", Some("SecondEmitter"), &[]),
    ];
    let ambiguous = collect(
        &e,
        None,
        &[(row("Methods", "ordinary", 23, true), conflicting, 7)],
    );
    assert!(ambiguous.opportunities.is_empty());
}

#[test]
fn empty_capture_and_candidate_generator_evidence_never_prove_execution() {
    let e = evidence();
    let empty: Evidence = serde_json::from_value(json!({"schema": EVIDENCE_SCHEMA, "sources": [], "generators": [], "generator_runs": [], "generator_links": []})).unwrap();
    let r = collect(&empty, None, &[]);
    assert_eq!(
        (
            r.source_declarations,
            r.generated_declarations,
            r.generator_descriptors
        ),
        (0, 0, 0)
    );
    assert!(r.attribute_occurrences.is_empty() && r.opportunities.is_empty());
    let mut candidate = association("producer_prefix_candidate", &["App"]);
    candidate.sources = vec![source("First", Some("Emitter"), &[])];
    let r = collect(
        &e,
        None,
        &[(row("Methods", "ordinary", 23, true), candidate, 8)],
    );
    let generator = finding(&r, "generator:Emitter");
    assert_eq!((generator.additive_bytes, generator.identities), (23, 1));
    assert_eq!(
        generator.evidence_tier,
        "producer_prefix_candidate+captured_generator_declaration"
    );
    assert_eq!(generator.streams, streams(&[("Methods", 23)]));
    assert_eq!(generator.proposed_savings_bytes, None);
}

#[test]
fn collector_memory_boundaries_return_resource_diagnostics() {
    let e = evidence();
    code(
        OpportunityCollector::new(&e, None, MIB - 1).map(|_| ()),
        "resource.opportunities",
    );
    for memory in [MIB, MIB + 1] {
        let mut c = OpportunityCollector::new(&e, None, memory).unwrap();
        c.observe(
            &row("Methods", "small", 3, true),
            &association("unmapped", &[]),
            1,
        )
        .unwrap();
        assert_eq!(c.finish().unwrap().accounted_bytes, 3);
    }
    let mut c = OpportunityCollector::new(&e, None, MIB).unwrap();
    let mut failure = None;
    for n in 0..600 {
        let name = format!("SmallFamily{n}<A>");
        let assembly = format!("Assembly{n}");
        match c.observe(
            &row("Methods", &name, 1, true),
            &association("candidate", &[&assembly]),
            n,
        ) {
            Ok(()) => {}
            Err(error) => {
                failure = Some((n, error));
                break;
            }
        }
    }
    let (ordinal, failure) = failure.expect("bounded distinct aggregates must exhaust 1 MiB");
    assert!(ordinal > 1 && ordinal < 600);
    assert_eq!(failure.diagnostic.code, "resource.opportunities");
    // Constructor policy storage and origins must also respect the reservation.
    let mut p = policy();
    for n in 0..64 {
        let mut r = rule(&format!("large-{n}"), &["x"], &[]);
        r.investigation = "x".repeat(4096);
        r.contains = (0..64).map(|_| "x".repeat(1024)).collect();
        p.rules.push(r);
    }
    validate_policy(&p).unwrap();
    code(
        OpportunityCollector::new(&e, Some(&p), MIB).map(|_| ()),
        "resource.opportunities",
    );
    let mut e = evidence();
    for n in 0..2100 {
        e.mappings
            .push(origin(&format!("A{n}"), "P/1", "compile", "t"));
    }
    code(
        OpportunityCollector::new(&e, None, MIB).map(|_| ()),
        "resource.opportunities",
    );
    // Attribute occurrence storage is deferred to fallible finish.
    let mut e = evidence();
    e.sources.push(source("Attributes", None, &[]));
    e.sources[0].attributes = (0..9000).map(|n| format!("Attribute{n}")).collect();
    let c = OpportunityCollector::new(&e, None, MIB).unwrap();
    code(c.finish(), "resource.opportunities");
    // Isolate capability materialization, with no attribute storage at finish.
    let e = evidence();
    let mut p = policy();
    for n in 0..64 {
        let mut rule = capability(&format!("cap-{n}"), &["A", "B"]);
        rule.title = "t".repeat(1024);
        rule.investigation = "i".repeat(4096);
        p.capabilities.push(rule);
    }
    validate_policy(&p).unwrap();
    let mut c = OpportunityCollector::new(&e, Some(&p), MIB).unwrap();
    for (assembly, bytes, ordinal) in [("A", 3, 0), ("B", 5, 1)] {
        c.observe(
            &row("Methods", assembly, bytes, true),
            &association("asserted", &[assembly]),
            ordinal,
        )
        .unwrap();
    }
    code(c.finish(), "resource.opportunities");
}

#[test]
fn aggregate_overflow_returns_opportunities_size() {
    let e = evidence();
    // Separate additive/overlap totals can fit while a single budget's stream overflows.
    let mut mixed = OpportunityCollector::new(&e, None, MEMORY).unwrap();
    mixed
        .observe(
            &row("Methods", "additive", u64::MAX, true),
            &association("asserted", &["A"]),
            0,
        )
        .unwrap();
    code(
        mixed.observe(
            &row("Methods", "overlap", 1, false),
            &association("asserted", &["A"]),
            1,
        ),
        "opportunities.size",
    );
    let mut c = OpportunityCollector::new(&e, None, MEMORY).unwrap();
    c.observe(
        &row("Methods", "one", u64::MAX, true),
        &association("asserted", &["A"]),
        0,
    )
    .unwrap();
    code(
        c.observe(
            &row("Blobs", "two", 1, true),
            &association("asserted", &["B"]),
            1,
        ),
        "opportunities.size",
    );
    for second_stream in ["ManifestResources", "FrozenObjects"] {
        let mut c = OpportunityCollector::new(&e, None, MEMORY).unwrap();
        c.observe(
            &row("ManifestResources", "one", u64::MAX, false),
            &association("asserted", &["A"]),
            0,
        )
        .unwrap();
        code(
            c.observe(
                &row(second_stream, "two", 1, false),
                &association("asserted", &["A"]),
                1,
            ),
            "opportunities.size",
        );
    }
}

#[test]
fn findings_and_capability_overflow_return_opportunities_size() {
    // Separate assembly/package keys isolate the common finding addition.
    let mut e = evidence();
    e.mappings = vec![
        origin("A", "PA", "compile", "t"),
        origin("B", "PB", "compile", "t"),
    ];
    let p = OpportunityPolicy {
        rules: vec![rule("overflow", &["match"], &[])],
        ..policy()
    };
    let mut c = OpportunityCollector::new(&e, Some(&p), MEMORY).unwrap();
    c.observe(
        &row("ManifestResources", "match-A", u64::MAX, false),
        &association("asserted", &["A"]),
        0,
    )
    .unwrap();
    code(
        c.observe(
            &row("FrozenObjects", "match-B", 1, false),
            &association("asserted", &["B"]),
            1,
        ),
        "opportunities.size",
    );
    let p = OpportunityPolicy {
        capabilities: vec![capability("overflow", &["A", "B"])],
        ..policy()
    };
    for mode in ["overlapping-total", "stream-total"] {
        let mut c = OpportunityCollector::new(&e, Some(&p), MEMORY).unwrap();
        for assembly in ["A", "B"] {
            c.observe(
                &row("Methods", assembly, 1, true),
                &association("asserted", &[assembly]),
                0,
            )
            .unwrap();
        }
        if mode == "overlapping-total" {
            for assembly in ["A", "B"] {
                c.observe(
                    &row("ManifestResources", assembly, u64::MAX / 2 + 1, false),
                    &association("asserted", &[assembly]),
                    1,
                )
                .unwrap();
            }
        } else {
            c.observe(
                &row("Methods", "special", u64::MAX - 1, false),
                &association("asserted", &["A"]),
                1,
            )
            .unwrap();
        }
        code(c.finish(), "opportunities.size");
    }
    let r = collect(
        &evidence(),
        None,
        &[
            (
                row("Methods", "max", u64::MAX, true),
                association("asserted", &["A"]),
                0,
            ),
            (
                row("Methods", "zero", 0, true),
                association("asserted", &["A"]),
                1,
            ),
        ],
    );
    assert_eq!(r.accounted_bytes, u64::MAX);
    assert_eq!(budget(&r, "assembly", "A", "", "asserted").identities, 2);
}

fn captured_generator_values() -> (Value, Value) {
    let expected = json!({
        "name": "Emitter", "version": "2.1", "assembly_path": "Emitter.dll", "project_path": "App.csproj",
        "target_assembly": "App", "target_assembly_path": "App.dll", "configuration": "Release",
        "target_framework": "net9.0", "status": "captured", "basis": "synthetic recorded build route",
        "execution_status": "unknown", "outputs": [{
            "path": "Widget.g.cs", "sha256": "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
            "build_match": "candidate", "pdb_checksums": [{
                "pdb_path": "App.pdb", "algorithm": "SHA256", "checksum": "1234",
                "status": "captured", "assembly_match": "unknown", "target_assembly": "App",
                "target_assembly_path": "App.dll"
            }]
        }]
    });
    let expected_link = json!({
        "generator": "Emitter", "output_path": "Widget.g.cs", "trigger_source": "Widget.cs",
        "trigger_type": "Widget", "trigger_member": "Run", "trigger_symbol": "App.Widget.Run",
        "rule": "explicit_trigger", "evidence_tier": "asserted", "basis": "supplied assertion"
    });
    (expected, expected_link)
}

#[test]
fn generator_capture_defaults_are_callable_but_not_execution_proof() {
    let run = GeneratorRun::default();
    let output = GeneratorOutput::default();
    let checksum = GeneratorChecksum::default();
    let link = GeneratorLink::default();
    assert_eq!(
        (
            run.name.as_str(),
            run.status.as_str(),
            run.basis.as_str(),
            run.execution_status.as_str()
        ),
        ("", "", "", "")
    );
    assert!(run.outputs.is_empty() && run.version.is_none() && run.target_assembly.is_none());
    assert!(
        output.path.as_os_str().is_empty()
            && output.sha256.is_none()
            && output.pdb_checksums.is_empty()
    );
    assert_eq!(output.build_match, "");
    assert_eq!(
        (
            checksum.algorithm.as_str(),
            checksum.checksum.as_str(),
            checksum.status.as_str(),
            checksum.assembly_match.as_str()
        ),
        ("", "", "", "")
    );
    assert_eq!(
        (
            link.generator.as_str(),
            link.rule.as_str(),
            link.evidence_tier.as_str(),
            link.basis.as_str()
        ),
        ("", "", "", "")
    );
    let absent: Evidence = serde_json::from_value(json!({"schema": EVIDENCE_SCHEMA})).unwrap();
    assert!(absent.generator_runs.is_empty() && absent.generator_links.is_empty());
    let serialized = serde_json::to_value(&absent).unwrap();
    assert!(
        serialized.get("generator_runs").is_none() && serialized.get("generator_links").is_none()
    );
    let (expected, expected_link) = captured_generator_values();
    let capture: GeneratorRun = serde_json::from_value(expected.clone()).unwrap();
    assert_eq!(serde_json::to_value(&capture).unwrap(), expected);
    let captured_link: GeneratorLink = serde_json::from_value(expected_link.clone()).unwrap();
    assert_eq!(serde_json::to_value(&captured_link).unwrap(), expected_link);
    let mut e = evidence();
    e.generator_runs.push(capture);
    e.generator_links.push(captured_link);
    let restored: Evidence = serde_json::from_value(serde_json::to_value(&e).unwrap()).unwrap();
    assert_eq!(
        serde_json::to_value(&restored.generator_runs).unwrap(),
        json!([expected])
    );
    assert_eq!(
        serde_json::to_value(&restored.generator_links).unwrap(),
        json!([expected_link])
    );
    e.generators.push(Generator {
        name: "DescriptorOnly".into(),
        version: "1".into(),
        ..Generator::default()
    });
    let r = collect(&e, None, &[]);
    assert_eq!(r.generator_descriptors, 1);
    assert_eq!(r.generated_declarations, 0);
    assert!(r.opportunities.is_empty());
    assert!(
        r.limitations
            .iter()
            .any(|s| s.contains("not proof a generator executed"))
    );
}

#[test]
fn generator_capture_models_reject_missing_and_unknown_fields() {
    let (expected, _) = captured_generator_values();
    for field in ["name", "status", "basis", "execution_status"] {
        let mut missing = expected.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<GeneratorRun>(missing)
                .unwrap_err()
                .to_string()
                .contains(field)
        );
    }
}

fn import_symbol_fixture(
    root: &Path,
    records: &[(&str, u32)],
) -> (
    PathBuf,
    vitnet_attribution::AttributionIndex,
    Vec<CoalescedIdentity>,
) {
    let mut image = common::Image::new();
    for (name, _) in records {
        image.method(name.as_bytes(), 11);
    }
    let mut bytes = image.bytes();
    // Guarded edits of the existing data-only fixture, not a new metadata parser.
    // A nonempty TypeDef owner permits the existing valid MethodDefs to resolve.
    assert_eq!(&bytes[798..800], &[0, 0]);
    bytes[798..800].copy_from_slice(&1_u16.to_le_bytes());
    let positions: Vec<_> = bytes
        .windows(6)
        .enumerate()
        .filter_map(|(offset, record)| {
            (record == [0xd0, 1, 0, 0, 0x0a, 0x20]).then_some(offset + 1)
        })
        .collect();
    assert_eq!(positions.len(), records.len());
    for (position, (_, token)) in positions.iter().zip(records) {
        bytes[*position..*position + 4].copy_from_slice(&token.to_le_bytes());
    }
    let artifact = root.join("symbols.mstat");
    fs::write(&artifact, bytes).unwrap();
    let mut input = evidence();
    let mut declaration = source("Box", None, &[]);
    declaration.assembly = "A".into();
    input.sources.push(declaration);
    input.artifacts.push(Artifact {
        kind: "mstat".into(),
        path: artifact,
        revision: None,
        blake3: None,
    });
    let input_path = write_evidence(root, &input);
    let directory = root.join("index");
    let manifest = import(&input_path, &directory, MEMORY, false).unwrap();
    let rows = fs::read_to_string(directory.join("identities.ndjson"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    (directory, manifest, rows)
}

fn symbol_payload(directory: &Path) -> Vec<Value> {
    fs::read_to_string(directory.join("symbols.ndjson"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn pin_symbol_payload(directory: &Path, descriptor: &mut SymbolSidecar) {
    let (length, hash) = vitnet_attribution::hash_file(&directory.join("symbols.ndjson")).unwrap();
    descriptor.payload_bytes = length;
    descriptor.payload_blake3 = hash;
}

fn pin_symbol_lookup(directory: &Path, descriptor: &mut SymbolSidecar) {
    descriptor.lookup_blake3 = vitnet_attribution::hash_file(&directory.join("symbols.idx"))
        .unwrap()
        .1;
}

#[test]
fn symbol_import_collapses_identical_tokens_and_preserves_distinct_candidates() {
    let root = tempfile::tempdir().unwrap();
    let name = "A_Box<int>__Run";
    let (directory, manifest, rows) = import_symbol_fixture(
        root.path(),
        &[
            (name, 0x0a00_0001),
            (name, 0x0a00_0001),
            (name, 0x0600_0001),
            (name, 0x0600_0002),
            ("Z_Other__Run", 0x0a00_0001),
        ],
    );
    let descriptor = manifest.symbols.as_ref().unwrap();
    let payload = symbol_payload(&directory);
    assert_eq!(descriptor.schema, "vitnet.symbol-sidecar.v1");
    assert_eq!((descriptor.records, payload.len()), (4, 5));
    assert_eq!(
        payload[0], payload[1],
        "duplicate lookup tokens must not delete original payload rows"
    );
    assert_eq!(
        vitnet_attribution::hash_file(&directory.join("symbols.ndjson")).unwrap(),
        (descriptor.payload_bytes, descriptor.payload_blake3.clone())
    );
    let lookup_bytes = fs::read(directory.join("symbols.idx")).unwrap();
    assert_eq!(lookup_bytes.len(), 4 * 40);
    assert_eq!(
        blake3::hash(&lookup_bytes).to_hex().to_string(),
        descriptor.lookup_blake3
    );
    let keys: Vec<_> = lookup_bytes
        .chunks_exact(40)
        .map(|record| {
            (
                record[..32].to_vec(),
                u64::from_le_bytes(record[32..].try_into().unwrap()),
            )
        })
        .collect();
    assert!(keys.windows(2).all(|pair| pair[0] < pair[1]));
    let mut lookup = SymbolLookup::open(&directory, descriptor, MEMORY).unwrap();
    lookup.check().unwrap();
    let entry = rows.iter().find(|entry| entry.identity == name).unwrap();
    assert_eq!((entry.bytes, entry.records), (44, 4));
    let candidates = lookup
        .get(&entry.stream, &entry.raw_identity_blake3)
        .unwrap();
    assert_eq!(
        candidates,
        [payload[0].clone(), payload[2].clone(), payload[3].clone()]
    );
    assert_eq!(
        candidates
            .iter()
            .map(|record| record["token"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        [0x0a00_0001, 0x0600_0001, 0x0600_0002]
    );
    let matcher = vitnet_attribution::Matcher::new(&manifest.evidence);
    let located = matcher.locate_entry(entry, Some(&mut lookup)).unwrap();
    assert_eq!(located.status, "ambiguous");
    assert_eq!(located.assemblies, ["A", "synthetic.mstat"]);
    assert!(located.basis.contains("incomplete/unsupported"));
    assert_eq!(located.sources[0].type_name, "Box");
    let fallback = matcher.locate_entry(entry, None).unwrap();
    assert_eq!(fallback.status, "producer_prefix_candidate");
    assert_eq!(fallback.assemblies, ["A"]);
    let conflicting = matcher.locate_symbols(entry, &candidates[1..]).unwrap();
    assert_eq!(conflicting.status, "managed_symbol_ambiguous");
    assert_eq!(conflicting.assemblies, ["synthetic.mstat"]);
    assert_eq!(
        serde_json::to_value(conflicting.sources).unwrap(),
        json!([])
    );
}

#[test]
fn symbol_lookup_rejects_hash_count_order_and_offset_corruption() {
    let root = tempfile::tempdir().unwrap();
    let (directory, manifest, _) = import_symbol_fixture(
        root.path(),
        &[
            ("A_Box<int>__Run", 0x0a00_0001),
            ("Z_Other__Run", 0x0a00_0001),
        ],
    );
    let original = manifest.symbols.unwrap();
    for field in [
        "schema",
        "records",
        "payload_bytes",
        "payload_blake3",
        "lookup_blake3",
    ] {
        let mut invalid = original.clone();
        match field {
            "schema" => invalid.schema = "vitnet.symbol-sidecar.v2".into(),
            "records" => invalid.records += 1,
            "payload_bytes" => invalid.payload_bytes += 1,
            "payload_blake3" => invalid.payload_blake3 = "00".repeat(32),
            _ => invalid.lookup_blake3 = "00".repeat(32),
        }
        code(
            SymbolLookup::open(&directory, &invalid, MEMORY).map(|_| ()),
            if field == "schema" {
                "symbols.schema"
            } else {
                "symbols.integrity"
            },
        );
    }
    let index_path = directory.join("symbols.idx");
    let original_bytes = fs::read(&index_path).unwrap();
    let mut reversed = original_bytes[40..].to_vec();
    reversed.extend_from_slice(&original_bytes[..40]);
    fs::write(&index_path, reversed).unwrap();
    let mut invalid = original.clone();
    pin_symbol_lookup(&directory, &mut invalid);
    code(
        SymbolLookup::open(&directory, &invalid, MEMORY).map(|_| ()),
        "symbols.integrity",
    );
    for offset in [original.payload_bytes, u64::MAX] {
        let mut bytes = original_bytes.clone();
        bytes[32..40].copy_from_slice(&offset.to_le_bytes());
        fs::write(&index_path, bytes).unwrap();
        pin_symbol_lookup(&directory, &mut invalid);
        code(
            SymbolLookup::open(&directory, &invalid, MEMORY).map(|_| ()),
            "symbols.integrity",
        );
    }
    fs::write(&index_path, &original_bytes).unwrap();
    let payload_path = directory.join("symbols.ndjson");
    let mut changed = fs::read(&payload_path).unwrap();
    changed[0] ^= 1;
    fs::write(&payload_path, changed).unwrap();
    code(
        SymbolLookup::open(&directory, &original, MEMORY).map(|_| ()),
        "symbols.integrity",
    );
}

#[test]
fn symbol_lookup_raw_keys_and_row_integrity_are_not_display_labels() {
    let root = tempfile::tempdir().unwrap();
    let (directory, manifest, rows) =
        import_symbol_fixture(root.path(), &[("A_Box<int>__Run", 0x0a00_0001)]);
    let descriptor = manifest.symbols.unwrap();
    let entry = &rows[0];
    let mut lookup = SymbolLookup::open(&directory, &descriptor, MEMORY).unwrap();
    assert_eq!(
        lookup.get("Types", &entry.raw_identity_blake3).unwrap(),
        Vec::<Value>::new()
    );
    assert_eq!(
        lookup
            .get("Methods", blake3::hash(b"different raw").to_hex().as_ref())
            .unwrap(),
        Vec::<Value>::new()
    );
    assert_eq!(
        lookup.get("Methods", &entry.identity).unwrap(),
        Vec::<Value>::new()
    );
    let path = directory.join("symbols.ndjson");
    let original = fs::read(&path).unwrap();
    let mut invalid = descriptor.clone();
    let mut mismatched = symbol_payload(&directory)[0].clone();
    for field in ["stream", "raw_identity_blake3"] {
        mismatched[field] = json!("wrong key");
        let mut bytes = serde_json::to_vec(&mismatched).unwrap();
        bytes.push(b'\n');
        fs::write(&path, bytes).unwrap();
        pin_symbol_payload(&directory, &mut invalid);
        let mut lookup = SymbolLookup::open(&directory, &invalid, MEMORY).unwrap();
        code(
            lookup.get(&entry.stream, &entry.raw_identity_blake3),
            "symbols.integrity",
        );
        let matcher = vitnet_attribution::Matcher::new(&manifest.evidence);
        code(
            matcher.locate_entry(entry, Some(&mut lookup)),
            "symbols.integrity",
        );
        mismatched = serde_json::from_slice(&original).unwrap();
    }
    for (bytes, expected) in [
        (b"not-json\n".to_vec(), "symbols.json"),
        (original[..original.len() - 1].to_vec(), "symbols.integrity"),
    ] {
        fs::write(&path, bytes).unwrap();
        pin_symbol_payload(&directory, &mut invalid);
        let mut lookup = SymbolLookup::open(&directory, &invalid, MEMORY).unwrap();
        code(
            lookup.get(&entry.stream, &entry.raw_identity_blake3),
            expected,
        );
    }
}

#[test]
fn symbol_lookup_resource_and_stale_boundaries_are_typed() {
    let root = tempfile::tempdir().unwrap();
    let (directory, manifest, _) =
        import_symbol_fixture(root.path(), &[("A_Box<int>__Run", 0x0a00_0001)]);
    let descriptor = manifest.symbols.unwrap();
    code(
        SymbolLookup::open(&directory, &descriptor, (64 << 10) - 1).map(|_| ()),
        "resource.symbols",
    );
    for memory in [64 << 10, (64 << 10) + 1] {
        SymbolLookup::open(&directory, &descriptor, memory)
            .unwrap()
            .check()
            .unwrap();
    }
    let mut invalid = descriptor.clone();
    invalid.records = u64::MAX;
    code(
        SymbolLookup::open(&directory, &invalid, MEMORY).map(|_| ()),
        "symbols.size",
    );
    invalid.records = 410; // 410 * 40 > 64 KiB / 4; 409 is admissible below.
    code(
        SymbolLookup::open(&directory, &invalid, 64 << 10).map(|_| ()),
        "resource.symbols",
    );
    let index_path = directory.join("symbols.idx");
    let record = fs::read(&index_path).unwrap();
    fs::write(&index_path, record.repeat(409)).unwrap();
    invalid.records = 409;
    pin_symbol_lookup(&directory, &mut invalid);
    SymbolLookup::open(&directory, &invalid, 64 << 10)
        .unwrap()
        .check()
        .unwrap();
    fs::write(&index_path, &record).unwrap();
    for name in ["symbols.ndjson", "symbols.idx"] {
        let lookup = SymbolLookup::open(&directory, &descriptor, MEMORY).unwrap();
        let path = directory.join(name);
        let original = fs::read(&path).unwrap();
        let mut changed = original.clone();
        changed.push(b'\n');
        fs::write(&path, changed).unwrap();
        code(lookup.check(), "symbols.stale");
        fs::write(&path, original).unwrap();
    }
}

#[test]
fn symbol_lookup_candidate_count_and_row_share_boundaries_are_explicit() {
    let root = tempfile::tempdir().unwrap();
    let (directory, manifest, rows) =
        import_symbol_fixture(root.path(), &[("A_Box<int>__Run", 0x0a00_0001)]);
    let mut descriptor = manifest.symbols.unwrap();
    let index_path = directory.join("symbols.idx");
    let record = fs::read(&index_path).unwrap();
    let original_candidate = symbol_payload(&directory)[0].clone();
    for count in [63, 64, 65] {
        fs::write(&index_path, record.repeat(count)).unwrap();
        descriptor.records = u64::try_from(count).unwrap();
        pin_symbol_lookup(&directory, &mut descriptor);
        let mut lookup = SymbolLookup::open(&directory, &descriptor, MEMORY).unwrap();
        let result = lookup.get(&rows[0].stream, &rows[0].raw_identity_blake3);
        if count <= 64 {
            let candidates = result.unwrap();
            assert_eq!(candidates.len(), count);
            assert!(
                candidates
                    .iter()
                    .all(|candidate| candidate == &original_candidate)
            );
        } else {
            code(result, "resource.symbols");
        }
    }
    let capacity = 1024 / descriptor.payload_bytes;
    for count in [capacity, capacity + 1] {
        fs::write(&index_path, record.repeat(usize::try_from(count).unwrap())).unwrap();
        descriptor.records = count;
        pin_symbol_lookup(&directory, &mut descriptor);
        let mut lookup = SymbolLookup::open(&directory, &descriptor, 64 << 10).unwrap();
        let result = lookup.get(&rows[0].stream, &rows[0].raw_identity_blake3);
        if count == capacity {
            assert_eq!(
                result.unwrap(),
                vec![original_candidate.clone(); usize::try_from(count).unwrap()]
            );
        } else {
            code(result, "resource.symbols");
        }
    }
}

#[test]
fn symbol_lookup_oversized_original_rows_never_become_truncated_candidates() {
    let root = tempfile::tempdir().unwrap();
    let name = format!("A_Box<int>__{}", "Run".repeat(400));
    let (directory, manifest, rows) = import_symbol_fixture(root.path(), &[(&name, 0x0a00_0001)]);
    let descriptor = manifest.symbols.unwrap();
    let mut bounded = SymbolLookup::open(&directory, &descriptor, 64 << 10).unwrap();
    code(
        bounded.get(&rows[0].stream, &rows[0].raw_identity_blake3),
        "symbols.integrity",
    );
    let mut complete = SymbolLookup::open(&directory, &descriptor, MEMORY).unwrap();
    let candidates = complete
        .get(&rows[0].stream, &rows[0].raw_identity_blake3)
        .unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0]["identity"], name);
    assert_eq!(candidates[0], symbol_payload(&directory)[0]);
}

#[test]
fn symbol_lookup_exact_row_byte_limits_preserve_complete_originals() {
    let root = tempfile::tempdir().unwrap();
    let (directory, manifest, rows) =
        import_symbol_fixture(root.path(), &[("opaque", 0x0a00_0001)]);
    let mut descriptor = manifest.symbols.unwrap();
    let mut candidate = symbol_payload(&directory)[0].clone();
    candidate["identity"] = json!("");
    let overhead = serde_json::to_vec(&candidate).unwrap().len() + 1;
    for total_bytes in [1023, 1024, 1025] {
        candidate["identity"] = json!("x".repeat(total_bytes - overhead));
        let mut bytes = serde_json::to_vec(&candidate).unwrap();
        bytes.push(b'\n');
        assert_eq!(bytes.len(), total_bytes);
        fs::write(directory.join("symbols.ndjson"), bytes).unwrap();
        pin_symbol_payload(&directory, &mut descriptor);
        let mut lookup = SymbolLookup::open(&directory, &descriptor, 64 << 10).unwrap();
        let result = lookup.get(&rows[0].stream, &rows[0].raw_identity_blake3);
        if total_bytes <= 1024 {
            assert_eq!(result.unwrap(), [candidate.clone()]);
        } else {
            code(result, "symbols.integrity");
        }
    }
}

#[test]
fn symbol_lookup_same_length_modified_payloads_are_stale_without_timing() {
    let root = tempfile::tempdir().unwrap();
    let (directory, manifest, _) = import_symbol_fixture(root.path(), &[("opaque", 0x0a00_0001)]);
    let descriptor = manifest.symbols.unwrap();
    for name in ["symbols.ndjson", "symbols.idx"] {
        let lookup = SymbolLookup::open(&directory, &descriptor, MEMORY).unwrap();
        let path = directory.join(name);
        let original = fs::read(&path).unwrap();
        let mut changed = original.clone();
        changed[0] ^= 1;
        fs::write(&path, changed).unwrap();
        // Deterministic filesystem timestamp, not a delay or a wall-clock race.
        let times = fs::FileTimes::new()
            .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000));
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_times(times)
            .unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            u64::try_from(original.len()).unwrap()
        );
        code(lookup.check(), "symbols.stale");
        fs::write(&path, original).unwrap();
    }
}

#[test]
fn empty_symbol_capture_is_distinct_from_missing_sidecar() {
    let root = tempfile::tempdir().unwrap();
    let (directory, manifest, rows) = import_symbol_fixture(root.path(), &[]);
    assert_eq!(rows.len(), 0);
    let descriptor = manifest.symbols.unwrap();
    assert_eq!((descriptor.records, descriptor.payload_bytes), (0, 0));
    let empty_hash = blake3::hash(&[]).to_hex().to_string();
    assert_eq!(descriptor.payload_blake3, empty_hash);
    assert_eq!(descriptor.lookup_blake3, empty_hash);
    let mut lookup = SymbolLookup::open(&directory, &descriptor, 64 << 10).unwrap();
    lookup.check().unwrap();
    assert_eq!(
        lookup.get("Methods", "unknown").unwrap(),
        Vec::<Value>::new()
    );
}

#[test]
fn symbol_lookup_rejects_descending_offsets_within_one_raw_key() {
    let root = tempfile::tempdir().unwrap();
    let (directory, manifest, _) =
        import_symbol_fixture(root.path(), &[("same", 0x0600_0001), ("same", 0x0600_0002)]);
    let mut descriptor = manifest.symbols.unwrap();
    let path = directory.join("symbols.idx");
    let bytes = fs::read(&path).unwrap();
    assert_eq!(bytes.len(), 80);
    assert_eq!(&bytes[..32], &bytes[40..72]);
    let mut reversed = bytes[40..].to_vec();
    reversed.extend_from_slice(&bytes[..40]);
    fs::write(&path, reversed).unwrap();
    pin_symbol_lookup(&directory, &mut descriptor);
    code(
        SymbolLookup::open(&directory, &descriptor, MEMORY).map(|_| ()),
        "symbols.integrity",
    );
}

#[test]
fn generator_output_checksum_link_models_are_strict() {
    let (expected, expected_link) = captured_generator_values();
    for (kind, required) in [
        ("output", vec!["path", "build_match"]),
        (
            "checksum",
            vec![
                "pdb_path",
                "algorithm",
                "checksum",
                "status",
                "assembly_match",
            ],
        ),
        (
            "link",
            vec!["generator", "output_path", "rule", "evidence_tier", "basis"],
        ),
    ] {
        let base = match kind {
            "output" => expected["outputs"][0].clone(),
            "checksum" => expected["outputs"][0]["pdb_checksums"][0].clone(),
            _ => expected_link.clone(),
        };
        for field in required {
            let mut missing = base.clone();
            missing.as_object_mut().unwrap().remove(field);
            let error = match kind {
                "output" => serde_json::from_value::<GeneratorOutput>(missing).unwrap_err(),
                "checksum" => serde_json::from_value::<GeneratorChecksum>(missing).unwrap_err(),
                _ => serde_json::from_value::<GeneratorLink>(missing).unwrap_err(),
            };
            assert!(error.to_string().contains(field));
        }
    }
    for kind in ["run", "output", "checksum", "link"] {
        let mut extra = match kind {
            "run" => expected.clone(),
            "output" => expected["outputs"][0].clone(),
            "checksum" => expected["outputs"][0]["pdb_checksums"][0].clone(),
            _ => expected_link.clone(),
        };
        extra["unexpected"] = json!(true);
        let error = match kind {
            "run" => serde_json::from_value::<GeneratorRun>(extra).unwrap_err(),
            "output" => serde_json::from_value::<GeneratorOutput>(extra).unwrap_err(),
            "checksum" => serde_json::from_value::<GeneratorChecksum>(extra).unwrap_err(),
            _ => serde_json::from_value::<GeneratorLink>(extra).unwrap_err(),
        };
        assert!(error.to_string().contains("unknown field"));
    }
}

fn assert_capture_path_import(has_legacy_descriptor: bool) {
    let root = tempfile::tempdir().unwrap();
    let mut input = evidence();
    let (run, link) = captured_generator_values();
    input
        .generator_runs
        .push(serde_json::from_value(run).unwrap());
    input
        .generator_links
        .push(serde_json::from_value(link).unwrap());
    for file in [
        "Emitter.dll",
        "App.csproj",
        "App.dll",
        "Widget.g.cs",
        "App.pdb",
        "Widget.cs",
    ] {
        fs::write(root.path().join(file), format!("captured data for {file}")).unwrap();
    }
    if has_legacy_descriptor {
        input.generators.push(Generator {
            name: "Emitter".into(),
            version: "2.1".into(),
            assembly_path: PathBuf::from("Emitter.dll"),
            ..Generator::default()
        });
    }
    let path = write_evidence(root.path(), &input);
    let imported = import(&path, &root.path().join("index"), MEMORY, false).unwrap();
    let run = &imported.evidence.generator_runs[0];
    assert_eq!(run.assembly_path, Some(root.path().join("Emitter.dll")));
    assert_eq!(run.project_path, Some(root.path().join("App.csproj")));
    assert_eq!(run.target_assembly_path, Some(root.path().join("App.dll")));
    assert_eq!(run.outputs[0].path, root.path().join("Widget.g.cs"));
    assert_eq!(
        run.outputs[0].pdb_checksums[0].pdb_path,
        root.path().join("App.pdb")
    );
    assert_eq!(
        run.outputs[0].pdb_checksums[0].target_assembly_path,
        Some(root.path().join("App.dll"))
    );
    assert_eq!(
        imported.evidence.generator_links[0].output_path,
        root.path().join("Widget.g.cs")
    );
    assert_eq!(
        imported.evidence.generator_links[0].trigger_source,
        Some(root.path().join("Widget.cs"))
    );
    for (kind, filename) in [("generator_output", "Widget.g.cs"), ("pdb", "App.pdb")] {
        let fingerprint = imported
            .artifacts
            .iter()
            .find(|artifact| artifact.kind == kind)
            .unwrap();
        let bytes = format!("captured data for {filename}").into_bytes();
        assert_eq!(fingerprint.path, root.path().join(filename));
        assert!(fingerprint.available);
        assert_eq!(
            fingerprint.file_bytes,
            Some(u64::try_from(bytes.len()).unwrap())
        );
        assert_eq!(
            fingerprint.blake3,
            Some(blake3::hash(&bytes).to_hex().to_string())
        );
    }
    assert_eq!(run.execution_status, "unknown");
    assert_eq!(imported.identities, 0);
}

#[test]
fn generator_capture_paths_and_fingerprints_do_not_require_legacy_descriptors() {
    assert_capture_path_import(false);
}

#[test]
fn generator_capture_paths_and_fingerprints_resolve_with_legacy_descriptors() {
    assert_capture_path_import(true);
}
