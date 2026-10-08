use std::fs;
use vitnet_dgml::{
    GraphSession, IncomingOptions, IndexControl, IndexOptions, SearchMode, SearchOptions,
    SearchRank, WhyOptions, build_index, prune_cache,
};

const GRAPH: &[u8] = br#"<DirectedGraph><Nodes>
<Node Id="0" Label="root"/><Node Id="1" Label="Alpha &amp; Beta"/>
<Node Id="2" Label="alpha other"/><Node Id="4" Label="other"/>
</Nodes><Links><Link Source="0" Target="1" Reason=""/><Link Source="1" Target="2" Reason="call"/></Links></DirectedGraph>"#;

#[test]
fn full_unicode_and_duplicate_labels_match_before_preview_and_cursor_bounds() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("unicode.xml");
    fs::write(&input, br#"<DirectedGraph><Nodes><Node Id="0" Label="&#x65E5;abc"/><Node Id="1" Label="&#x65E5;abc"/></Nodes></DirectedGraph>"#).unwrap();
    let path = build_index(
        &input,
        &IndexOptions {
            cache_root: directory.path().join("cache"),
            memory_limit: 16 << 20,
            selected_entry: None,
            strict_hash: false,
            control: IndexControl::default(),
        },
    )
    .unwrap()
    .index_directory;
    let mut session = GraphSession::open(&path, 16 << 20).unwrap();
    let report = session
        .search(
            "日abc",
            &SearchOptions {
                mode: SearchMode::Exact,
                preview_bytes: 2,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        report
            .entries
            .iter()
            .map(|node| node.node_id)
            .collect::<Vec<_>>(),
        [0, 1]
    );
    assert_eq!(report.entries[0].label, "");
    assert_eq!(report.entries[0].label_bytes, 6);
    assert!(report.entries[0].truncated);
    assert_eq!(report.stop_reason, "complete");
    assert_eq!(
        session
            .search(
                "abc",
                &SearchOptions {
                    after_id: Some(u64::MAX),
                    ..Default::default()
                }
            )
            .unwrap()
            .entries,
        vec![]
    );
    let generation = session.generation.clone();
    drop(session);
    let strings = path
        .join("generations")
        .join(generation)
        .join("strings.bin");
    let mut bytes = fs::read(&strings).unwrap();
    bytes[0] = 0xff;
    fs::write(strings, bytes).unwrap();
    let mut session = GraphSession::open(&path, 16 << 20).unwrap();
    assert_eq!(
        session
            .search(
                "0",
                &SearchOptions {
                    mode: SearchMode::Id,
                    ..Default::default()
                }
            )
            .unwrap_err()
            .diagnostic
            .code,
        "dgml.cache.utf8"
    );
}

fn index(directory: &std::path::Path) -> std::path::PathBuf {
    index_text(directory, GRAPH)
}

#[test]
fn prepared_contains_preserves_unicode_lowering_and_complete_label_validation() {
    let directory = tempfile::tempdir().unwrap();
    let path = index_text(
        directory.path(),
        br#"<DirectedGraph><Nodes>
<Node Id="0" Label="needle repeated needle"/>
<Node Id="1" Label="&#x212A;elvin"/>
<Node Id="2" Label="other"/></Nodes></DirectedGraph>"#,
    );
    let mut session = GraphSession::open(&path, 16 << 20).unwrap();
    for (query, ignore_case, expected) in [
        ("needle", false, vec![0]),
        ("KELVIN", true, vec![1]),
        ("kelvin", false, vec![]),
        ("missing", true, vec![]),
    ] {
        let report = session
            .search(
                query,
                &SearchOptions {
                    ignore_case,
                    count_all: true,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(
            report
                .entries
                .iter()
                .map(|node| node.node_id)
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(report.scanned_nodes, 3);
        assert_eq!(report.matched_nodes, expected.len() as u64);
    }
    let generation = session.generation.clone();
    drop(session);
    let strings = path
        .join("generations")
        .join(generation)
        .join("strings.bin");
    let mut bytes = fs::read(&strings).unwrap();
    bytes[0] = 0xff;
    fs::write(strings, bytes).unwrap();
    let mut session = GraphSession::open(&path, 16 << 20).unwrap();
    assert_eq!(
        session
            .search("no-match", &SearchOptions::default())
            .unwrap_err()
            .diagnostic
            .code,
        "dgml.cache.utf8"
    );
}

fn index_text(directory: &std::path::Path, text: &[u8]) -> std::path::PathBuf {
    let input = directory.join("graph.xml");
    fs::write(&input, text).unwrap();
    build_index(
        &input,
        &IndexOptions {
            cache_root: directory.join("cache"),
            memory_limit: 16 << 20,
            selected_entry: None,
            strict_hash: false,
            control: IndexControl::default(),
        },
    )
    .unwrap()
    .index_directory
}

#[test]
#[allow(clippy::too_many_lines)]
fn complete_counts_and_fan_in_rank_are_not_display_limited() {
    let directory = tempfile::tempdir().unwrap();
    let path = index_text(
        directory.path(),
        br#"<DirectedGraph><Nodes>
<Node Id="0" Label="root"/><Node Id="1" Label="match first"/><Node Id="2" Label="match second"/>
<Node Id="4" Label="match fourth"/></Nodes><Links>
<Link Source="0" Target="1" Reason=""/><Link Source="0" Target="2" Reason="call"/>
<Link Source="1" Target="2" Reason="Primary"/><Link Source="3" Target="2" Reason="Secondary"/>
<Link Source="0" Target="4" Reason=""/></Links></DirectedGraph>"#,
    );
    let mut session = GraphSession::open(&path, 16 << 20).unwrap();
    let ranked = session
        .search(
            "match",
            &SearchOptions {
                rank: SearchRank::Incoming,
                limit: 1,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(ranked.scanned_nodes, 5);
    assert_eq!(ranked.matched_nodes, 3);
    assert_eq!(ranked.matched_incoming_edges, 5);
    assert_eq!(ranked.omitted_matches, 2);
    assert_eq!(ranked.entries[0].node_id, 2);
    assert_eq!(ranked.entries[0].incoming_edges, 3);
    assert_eq!(ranked.stop_reason, "complete");
    assert_eq!(ranked.next_after_id, None);
    let tied = session
        .search(
            "match",
            &SearchOptions {
                rank: SearchRank::Incoming,
                limit: 2,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        tied.entries
            .iter()
            .map(|entry| entry.node_id)
            .collect::<Vec<_>>(),
        [2, 1]
    );
    assert_eq!(tied.matched_nodes, 3);
    assert_eq!(tied.matched_incoming_edges, 5);
    assert_eq!(tied.omitted_matches, 1);
    let counted = session
        .search(
            "match",
            &SearchOptions {
                count_all: true,
                limit: 1,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(counted.entries[0].node_id, 1);
    assert_eq!(counted.matched_nodes, 3);
    let partial = session
        .search(
            "match",
            &SearchOptions {
                rank: SearchRank::Incoming,
                limit: 1,
                max_scanned: 2,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(partial.stop_reason, "max_scanned");
    assert_eq!(partial.matched_nodes, 1);
    assert_eq!(partial.next_after_id, Some(1));
    let page = session
        .incoming(
            2,
            &IncomingOptions {
                limit: 2,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(page.total_edges, 3);
    assert_eq!(page.edges.len(), 2);
    assert_eq!(page.next_after_edge, Some(1));
    assert_eq!(page.edges[1].reason, "Primary");
    assert_eq!(page.edges[1].source_id, 1);
    assert_eq!(page.edges[1].target_id, 2);
    let last = session
        .incoming(
            2,
            &IncomingOptions {
                after_edge: page.next_after_edge,
                generation: Some(page.generation),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(last.edges[0].ordinal, 2);
    assert_eq!(last.edges[0].source_id, 3);
    assert!(last.edges[0].source.is_none());
    assert_eq!(last.edges[0].reason, "Secondary");
    assert_eq!(last.stop_reason, "complete");
    assert_eq!(last.next_after_edge, None);
    assert!(
        session
            .incoming(
                2,
                &IncomingOptions {
                    after_edge: Some(u64::MAX),
                    ..Default::default()
                }
            )
            .unwrap()
            .edges
            .is_empty()
    );
}

#[test]
fn batch_shares_generation_order_and_total_budgets_and_rejects_invalid_inputs() {
    let directory = tempfile::tempdir().unwrap();
    let path = index(directory.path());
    let mut session = GraphSession::open(&path, 16 << 20).unwrap();
    let batch = session.batch(&[2, 1, 2], &WhyOptions::default()).unwrap();
    assert_eq!(
        batch
            .reports
            .iter()
            .map(|item| item.node.node_id)
            .collect::<Vec<_>>(),
        [2, 1, 2]
    );
    assert_eq!(batch.requested_nodes, 3);
    assert_eq!(batch.examined_edges, 5);
    assert_eq!(batch.visited_nodes, 8);
    assert!(
        batch
            .reports
            .iter()
            .all(|item| item.generation == batch.generation)
    );
    let bounded = session
        .batch(
            &[2, 1],
            &WhyOptions {
                max_edges: 1,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(bounded.reports.len(), 1);
    assert_eq!(bounded.stop_reason, "max_edges");
    assert_eq!(bounded.examined_edges, 1);
    assert_eq!(bounded.reports[0].stop_reason, "max_edges");
    assert!(session.batch(&[], &WhyOptions::default()).is_err());
    assert!(session.batch(&[2; 129], &WhyOptions::default()).is_err());
    assert_eq!(
        session
            .batch(&[3], &WhyOptions::default())
            .unwrap_err()
            .diagnostic
            .code,
        "dgml.query.node"
    );
    assert_eq!(
        session
            .incoming(
                1,
                &IncomingOptions {
                    generation: Some("stale".into()),
                    ..Default::default()
                }
            )
            .unwrap_err()
            .diagnostic
            .code,
        "dgml.query.generation"
    );
    assert!(
        session
            .incoming(
                1,
                &IncomingOptions {
                    limit: 0,
                    ..Default::default()
                }
            )
            .is_err()
    );
    assert!(
        session
            .incoming(
                1,
                &IncomingOptions {
                    timeout_ms: 0,
                    ..Default::default()
                }
            )
            .is_err()
    );
    assert!(
        session
            .incoming(0, &IncomingOptions::default())
            .unwrap()
            .edges
            .is_empty()
    );
}
#[test]
fn search_pages_full_labels_by_numeric_cursor_and_handles_sparse_ids() {
    let directory = tempfile::tempdir().unwrap();
    let path = index(directory.path());
    let mut session = GraphSession::open(&path, 16 << 20).unwrap();
    let options = SearchOptions {
        ignore_case: true,
        limit: 1,
        preview_bytes: 3,
        ..Default::default()
    };
    let first = session.search("ALPHA", &options).unwrap();
    assert_eq!(first.entries[0].node_id, 1);
    assert_eq!(first.entries[0].label, "Alp");
    assert!(first.entries[0].truncated);
    assert_eq!(first.entries[0].incoming_edges, 1);
    assert_eq!(first.stop_reason, "limit");
    let next = session
        .search(
            "ALPHA",
            &SearchOptions {
                after_id: first.next_after_id,
                generation: Some(first.generation),
                ..options.clone()
            },
        )
        .unwrap();
    assert_eq!(next.entries[0].node_id, 2);
    let final_page = session
        .search(
            "ALPHA",
            &SearchOptions {
                after_id: next.next_after_id,
                ..options
            },
        )
        .unwrap();
    assert_eq!(final_page.entries, vec![]);
    assert_eq!(final_page.stop_reason, "complete");
    assert_eq!(final_page.next_after_id, None);
    let exact = session
        .search(
            "Alpha & Beta",
            &SearchOptions {
                mode: SearchMode::Exact,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(exact.entries.len(), 1);
    let prefix = session
        .search(
            "alpha",
            &SearchOptions {
                mode: SearchMode::Prefix,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(prefix.entries[0].node_id, 2);
    let absent = session
        .search(
            "3",
            &SearchOptions {
                mode: SearchMode::Id,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(absent.entries, vec![]);
}

#[test]
fn search_reports_work_limits_and_rejects_generation_and_corruption() {
    let directory = tempfile::tempdir().unwrap();
    let path = index(directory.path());
    let mut session = GraphSession::open(&path, 16 << 20).unwrap();
    let report = session
        .search(
            "missing",
            &SearchOptions {
                max_scanned: 2,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(report.scanned_nodes, 2);
    assert_eq!(report.stop_reason, "max_scanned");
    assert_eq!(report.next_after_id, Some(1));
    assert_eq!(
        session
            .search(
                "root",
                &SearchOptions {
                    generation: Some("different".into()),
                    ..Default::default()
                }
            )
            .unwrap_err()
            .diagnostic
            .code,
        "dgml.query.generation"
    );
    assert_eq!(
        session
            .search(
                "invalid",
                &SearchOptions {
                    mode: SearchMode::Id,
                    ..Default::default()
                }
            )
            .unwrap_err()
            .diagnostic
            .code,
        "dgml.query.id"
    );
    assert!(
        session
            .search(
                "root",
                &SearchOptions {
                    limit: usize::MAX,
                    ..Default::default()
                }
            )
            .unwrap_err()
            .diagnostic
            .code
            .starts_with("resource.")
    );
    let generation = session.generation.clone();
    drop(session);
    fs::write(
        path.join("generations")
            .join(generation)
            .join("target-offsets.bin"),
        b"bad",
    )
    .unwrap();
    assert_eq!(
        GraphSession::open(&path, 16 << 20)
            .err()
            .unwrap()
            .diagnostic
            .code,
        "dgml.cache.structure"
    );
}

#[test]
fn why_preserves_reason_direction_bounds_and_reader_lifetime() {
    let directory = tempfile::tempdir().unwrap();
    let path = index(directory.path());
    let mut session = GraphSession::open(&path, 16 << 20).unwrap();
    let report = session.why(2, &WhyOptions::default()).unwrap();
    assert_eq!(report.paths.len(), 1);
    assert_eq!(report.paths[0].root_kind, "nativeaot_empty_reason_root");
    assert_eq!(
        report.paths[0]
            .nodes
            .iter()
            .map(|node| node.node_id)
            .collect::<Vec<_>>(),
        [0, 1, 2]
    );
    assert_eq!(report.paths[0].reasons, ["", "call"]);
    assert_eq!(report.paths[0].reason_bytes, [0, 4]);
    assert_eq!(report.paths[0].reasons_truncated, [false, false]);
    assert_eq!(report.stop_reason, "complete");
    assert_eq!(
        session
            .why(
                2,
                &WhyOptions {
                    max_depth: 0,
                    ..Default::default()
                }
            )
            .unwrap()
            .stop_reason,
        "max_depth"
    );
    assert_eq!(
        session
            .why(
                2,
                &WhyOptions {
                    max_visited: 1,
                    ..Default::default()
                }
            )
            .unwrap()
            .stop_reason,
        "max_visited"
    );
    assert_eq!(
        session
            .why(
                2,
                &WhyOptions {
                    max_edges: 1,
                    ..Default::default()
                }
            )
            .unwrap()
            .stop_reason,
        "max_edges"
    );
    let structural = session.why(4, &WhyOptions::default()).unwrap();
    assert_eq!(structural.paths[0].root_kind, "zero_in_degree_candidate");
    assert_eq!(
        session
            .why(3, &WhyOptions::default())
            .unwrap_err()
            .diagnostic
            .code,
        "dgml.query.node"
    );
    assert_eq!(
        prune_cache(&path).unwrap_err().diagnostic.code,
        "dgml.index.locked"
    );
    drop(session);
    assert!(prune_cache(&path).is_ok());
}

#[test]
fn why_terminates_cycles_and_reports_unresolved_sources() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("cycle.xml");
    fs::write(&input, br#"<DirectedGraph><Nodes><Node Id="0" Label="a"/><Node Id="1" Label="b"/></Nodes><Links><Link Source="0" Target="1" Reason="Primary"/><Link Source="1" Target="0" Reason="Secondary"/><Link Source="3" Target="0" Reason="missing"/></Links></DirectedGraph>"#).unwrap();
    let path = build_index(
        &input,
        &IndexOptions {
            cache_root: directory.path().join("cache"),
            memory_limit: 16 << 20,
            selected_entry: None,
            strict_hash: false,
            control: IndexControl::default(),
        },
    )
    .unwrap()
    .index_directory;
    let mut session = GraphSession::open(&path, 16 << 20).unwrap();
    let report = session.why(0, &WhyOptions::default()).unwrap();
    assert!(report.paths.is_empty());
    assert_eq!(report.repeated_nodes, 1);
    assert_eq!(report.missing_nodes, 1);
    assert_eq!(report.visited_nodes, 2);
    assert_eq!(report.stop_reason, "complete");
}
