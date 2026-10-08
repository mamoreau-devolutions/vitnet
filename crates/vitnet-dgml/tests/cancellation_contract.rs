//! Deterministic cooperative query cancellation; no sleeps, corpus or sockets.
use std::fs;
use std::path::{Path, PathBuf};
use vitnet_dgml::{
    GraphSession, IncomingOptions, IndexControl, IndexOptions, SearchMode, SearchOptions,
    SearchRank, WhyOptions, build_index,
};

const MEMORY: u64 = 32 << 20;
const GRAPH: &str = r#"<DirectedGraph><Nodes>
<Node Id="0" Label="root"/><Node Id="1" Label="Owner"/><Node Id="2" Label="target"/>
<Node Id="4" Label="leaf"/><Node Id="5" Label="cycle A"/><Node Id="6" Label="cycle B"/>
</Nodes><Links>
<Link Source="0" Target="1" Reason=""/>
<Link Source="1" Target="2" Reason="Primary"/>
<Link Source="1" Target="2" Reason="Secondary"/>
<Link Source="5" Target="6" Reason="loop B"/>
<Link Source="6" Target="5" Reason="loop A"/>
</Links></DirectedGraph>"#;

fn index(root: &Path) -> PathBuf {
    let input = root.join("graph.dgml");
    fs::write(&input, GRAPH).unwrap();
    build_index(
        &input,
        &IndexOptions {
            cache_root: root.join("cache"),
            memory_limit: MEMORY,
            selected_entry: None,
            strict_hash: false,
            control: IndexControl::default(),
        },
    )
    .unwrap()
    .index_directory
}

fn cancelled(session: &mut GraphSession) -> IndexControl {
    let control = IndexControl::default();
    session.set_control(control.clone());
    // Cancel the external clone, not the value moved into the session.
    control.cancel();
    control
}

#[test]
fn cancelled_search_modes_preserve_cursors_without_scanning_or_returning_matches() {
    let root = tempfile::tempdir().unwrap();
    let mut session = GraphSession::open(&index(root.path()), MEMORY).unwrap();
    let control = cancelled(&mut session);
    for (mode, query) in [
        (SearchMode::Id, "2"),
        (SearchMode::Exact, "target"),
        (SearchMode::Prefix, "tar"),
        (SearchMode::Contains, "arg"),
    ] {
        for after_id in [None, Some(0), Some(u64::MAX)] {
            for rank in [SearchRank::Id, SearchRank::Incoming] {
                let report = session
                    .search(
                        query,
                        &SearchOptions {
                            mode,
                            after_id,
                            rank,
                            count_all: true,
                            ..Default::default()
                        },
                    )
                    .unwrap();
                assert_eq!(report.schema, "vitnet.dgml-search.v1");
                assert_eq!(report.generation, session.generation);
                assert_eq!(report.query, query);
                assert_eq!(report.rank, rank);
                assert_eq!(report.stop_reason, "cancelled");
                assert_eq!(report.next_after_id, after_id);
                assert_eq!(report.entries.len(), 0);
                assert_eq!(report.scanned_nodes, 0);
                assert_eq!(report.matched_nodes, 0);
                assert_eq!(report.matched_incoming_edges, 0);
                assert_eq!(report.omitted_matches, 0);
            }
        }
    }
    assert!(control.is_cancelled());
}

#[test]
fn replacing_cancelled_control_restores_queries_without_resetting_the_old_signal() {
    let root = tempfile::tempdir().unwrap();
    let mut session = GraphSession::open(&index(root.path()), MEMORY).unwrap();
    let old = cancelled(&mut session);
    let replacement = IndexControl::default();
    session.set_control(replacement.clone());
    let options = SearchOptions {
        mode: SearchMode::Id,
        ..Default::default()
    };
    let report = session.search("2", &options).unwrap();
    assert_eq!(report.stop_reason, "complete");
    assert_eq!(report.entries.len(), 1);
    assert_eq!(report.entries[0].node_id, 2);
    assert_eq!(report.entries[0].label, "target");
    assert_eq!(report.entries[0].incoming_edges, 2);
    assert_eq!(report.next_after_id, None);
    for (mode, query) in [
        (SearchMode::Exact, "target"),
        (SearchMode::Prefix, "tar"),
        (SearchMode::Contains, "arg"),
    ] {
        let label = session
            .search(
                query,
                &SearchOptions {
                    mode,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(label.stop_reason, "complete");
        assert_eq!(label.entries.len(), 1);
        assert_eq!(label.entries[0].node_id, 2);
        assert_eq!(label.entries[0].label, "target");
        assert_eq!(label.entries[0].incoming_edges, 2);
        assert_eq!(label.scanned_nodes, 7);
        assert_eq!(label.matched_nodes, 1);
        assert_eq!(label.matched_incoming_edges, 2);
        assert_eq!(label.omitted_matches, 0);
        assert_eq!(label.next_after_id, None);
    }
    assert!(old.is_cancelled());
    assert!(!replacement.is_cancelled());
    old.cancel(); // An old capability cannot cancel a replacement query.
    assert_eq!(
        session.search("2", &options).unwrap().entries,
        report.entries
    );
    replacement.cancel();
    let stopped = session.search("2", &options).unwrap();
    assert_eq!(stopped.stop_reason, "cancelled");
    assert_eq!(stopped.entries.len(), 0);
}

#[test]
fn cancelled_incoming_leaf_and_nonleaf_preserve_metadata_and_cursor() {
    let root = tempfile::tempdir().unwrap();
    let mut session = GraphSession::open(&index(root.path()), MEMORY).unwrap();
    cancelled(&mut session);
    for (id, label, count) in [(4, "leaf", 0), (2, "target", 2)] {
        for after_edge in [None, Some(0), Some(u64::MAX)] {
            let report = session
                .incoming(
                    id,
                    &IncomingOptions {
                        after_edge,
                        ..Default::default()
                    },
                )
                .unwrap();
            assert_eq!(report.schema, "vitnet.dgml-incoming.v1");
            assert_eq!(report.generation, session.generation);
            assert_eq!(report.node.node_id, id);
            assert_eq!(report.node.label, label);
            assert_eq!(report.node.incoming_edges, count);
            assert_eq!(report.total_edges, count);
            assert_eq!(report.stop_reason, "cancelled");
            assert_eq!(report.next_after_edge, after_edge);
            assert!(report.edges.is_empty());
            assert!(
                report
                    .caveat
                    .contains("Primary/Secondary dependencies can be conjunctive.")
            );
            assert!(
                report
                    .caveat
                    .contains("Fan-in is not bytes or removable-size evidence.")
            );
        }
    }
}

#[test]
fn cancelled_why_never_claims_a_root_or_dependency_witness() {
    let root = tempfile::tempdir().unwrap();
    let mut session = GraphSession::open(&index(root.path()), MEMORY).unwrap();
    cancelled(&mut session);
    for (id, label) in [(0, "root"), (2, "target"), (5, "cycle A")] {
        let report = session.why(id, &WhyOptions::default()).unwrap();
        assert_eq!(report.schema, "vitnet.dgml-why.v1");
        assert_eq!(report.generation, session.generation);
        assert_eq!(report.node.node_id, id);
        assert_eq!(report.node.label, label);
        assert_eq!(report.stop_reason, "cancelled");
        assert!(report.paths.is_empty());
        assert_eq!(report.visited_nodes, 1); // Selected node, not a traversed witness.
        assert_eq!(report.examined_edges, 0);
        assert_eq!(report.repeated_nodes, 0);
        assert_eq!(report.missing_nodes, 0);
        assert!(report.caveat.contains("conjunctions"));
        assert!(report.caveat.contains("not byte sizes"));
    }
}

#[test]
fn cancelled_batch_stops_before_the_first_node_and_replacement_restores_input_order() {
    let root = tempfile::tempdir().unwrap();
    let mut session = GraphSession::open(&index(root.path()), MEMORY).unwrap();
    cancelled(&mut session);
    // An absent first node would throw if batch accidentally entered why().
    let report = session.batch(&[999, 2], &WhyOptions::default()).unwrap();
    assert_eq!(report.schema, "vitnet.dgml-batch.v1");
    assert_eq!(report.generation, session.generation);
    assert_eq!(report.requested_nodes, 2);
    assert_eq!(report.stop_reason, "cancelled");
    assert!(report.reports.is_empty());
    assert_eq!(report.examined_edges, 0);
    assert_eq!(report.visited_nodes, 0);
    session.set_control(IndexControl::default());
    let resumed = session.batch(&[2, 4], &WhyOptions::default()).unwrap();
    assert_eq!(resumed.stop_reason, "complete");
    assert_eq!(resumed.requested_nodes, 2);
    assert_eq!(
        resumed
            .reports
            .iter()
            .map(|r| r.node.node_id)
            .collect::<Vec<_>>(),
        [2, 4]
    );
    assert_eq!(resumed.examined_edges, 3);
    assert_eq!(resumed.visited_nodes, 4);
    assert_eq!(resumed.reports[0].paths[0].reasons, ["", "Primary"]);
    assert_eq!(
        resumed.reports[1].paths[0].root_kind,
        "zero_in_degree_candidate"
    );
}

#[test]
fn cancelled_controls_do_not_bypass_generation_or_option_validation() {
    let root = tempfile::tempdir().unwrap();
    let mut session = GraphSession::open(&index(root.path()), MEMORY).unwrap();
    cancelled(&mut session);
    let search = SearchOptions {
        generation: Some("wrong".into()),
        ..Default::default()
    };
    let incoming = IncomingOptions {
        generation: Some("wrong".into()),
        ..Default::default()
    };
    let why = WhyOptions {
        generation: Some("wrong".into()),
        ..Default::default()
    };
    for error in [
        session.search("target", &search).unwrap_err(),
        session.incoming(2, &incoming).unwrap_err(),
        session.why(2, &why).unwrap_err(),
        session.batch(&[2], &why).unwrap_err(),
    ] {
        assert_eq!(error.diagnostic.code, "dgml.query.generation");
    }
    assert_eq!(
        session
            .search("", &SearchOptions::default())
            .unwrap_err()
            .diagnostic
            .code,
        "dgml.query.options"
    );
    assert_eq!(
        session
            .incoming(
                2,
                &IncomingOptions {
                    timeout_ms: 0,
                    ..Default::default()
                }
            )
            .unwrap_err()
            .diagnostic
            .code,
        "dgml.query.options"
    );
    assert_eq!(
        session
            .why(
                2,
                &WhyOptions {
                    max_paths: 0,
                    ..Default::default()
                }
            )
            .unwrap_err()
            .diagnostic
            .code,
        "resource.memory_limit"
    );
    assert_eq!(
        session
            .batch(&[], &WhyOptions::default())
            .unwrap_err()
            .diagnostic
            .code,
        "resource.memory_limit"
    );
    assert_eq!(
        session
            .incoming(3, &IncomingOptions::default())
            .unwrap_err()
            .diagnostic
            .code,
        "dgml.query.node"
    );
    assert_eq!(
        session
            .why(3, &WhyOptions::default())
            .unwrap_err()
            .diagnostic
            .code,
        "dgml.query.node"
    );
}

#[test]
fn resumed_traversal_preserves_parallel_reasons_cycles_and_conditional_caveat() {
    let root = tempfile::tempdir().unwrap();
    let mut session = GraphSession::open(&index(root.path()), MEMORY).unwrap();
    cancelled(&mut session);
    session.set_control(IndexControl::default());
    let incoming = session.incoming(2, &IncomingOptions::default()).unwrap();
    assert_eq!(incoming.stop_reason, "complete");
    assert_eq!(incoming.total_edges, 2);
    assert_eq!(incoming.next_after_edge, None);
    assert_eq!(
        incoming
            .edges
            .iter()
            .map(|edge| (
                edge.ordinal,
                edge.source_id,
                edge.target_id,
                edge.reason.as_str()
            ))
            .collect::<Vec<_>>(),
        [(0, 1, 2, "Primary"), (1, 1, 2, "Secondary")]
    );
    assert_eq!(incoming.edges[0].source.as_ref().unwrap().label, "Owner");
    assert_eq!(incoming.edges[0].reason_bytes, 7);
    assert_eq!(incoming.edges[1].reason_bytes, 9);
    assert!(incoming.edges.iter().all(|edge| !edge.reason_truncated));
    assert!(
        incoming
            .caveat
            .contains("Primary/Secondary dependencies can be conjunctive.")
    );
    assert!(
        incoming
            .caveat
            .contains("Fan-in is not bytes or removable-size evidence.")
    );
    let witness = session.why(2, &WhyOptions::default()).unwrap();
    assert_eq!(witness.stop_reason, "complete");
    assert_eq!(witness.paths.len(), 1);
    assert_eq!(witness.paths[0].root_kind, "nativeaot_empty_reason_root");
    assert_eq!(
        witness.paths[0]
            .nodes
            .iter()
            .map(|n| n.node_id)
            .collect::<Vec<_>>(),
        [0, 1, 2]
    );
    assert_eq!(witness.paths[0].reasons, ["", "Primary"]);
    assert_eq!(witness.paths[0].reason_bytes, [0, 7]);
    assert_eq!(witness.paths[0].reasons_truncated, [false, false]);
    assert_eq!(witness.examined_edges, 3);
    assert_eq!(witness.repeated_nodes, 1);
    assert!(witness.caveat.contains(
        "Primary/Secondary combined nodes encode conjunctions, not independent sufficient causes."
    ));
    assert!(
        witness
            .caveat
            .contains("zero-in-degree terminals are candidates only.")
    );
    assert!(
        witness
            .caveat
            .contains("Dependency counts are not byte sizes.")
    );
    let cycle = session.why(5, &WhyOptions::default()).unwrap();
    assert_eq!(cycle.stop_reason, "complete");
    assert!(cycle.paths.is_empty());
    assert_eq!(cycle.visited_nodes, 2);
    assert_eq!(cycle.examined_edges, 2);
    assert_eq!(cycle.repeated_nodes, 1);
    assert_eq!(cycle.missing_nodes, 0);
}

#[test]
fn empty_partial_search_pages_retain_sparse_slot_progress_and_scan_boundary() {
    let root = tempfile::tempdir().unwrap();
    let mut session = GraphSession::open(&index(root.path()), MEMORY).unwrap();
    let mut after_id = None;
    for (scanned, cursor, reason) in [
        (2, Some(1), "max_scanned"),
        (2, Some(3), "max_scanned"), // Includes absent node slot 3.
        (2, Some(5), "max_scanned"),
        (1, None, "complete"),
    ] {
        let report = session
            .search(
                "absent needle",
                &SearchOptions {
                    max_scanned: 2,
                    after_id,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(report.entries.len(), 0);
        assert_eq!(report.scanned_nodes, scanned);
        assert_eq!(report.next_after_id, cursor);
        assert_eq!(report.stop_reason, reason);
        assert_eq!(report.matched_nodes, 0);
        after_id = cursor;
    }
}
