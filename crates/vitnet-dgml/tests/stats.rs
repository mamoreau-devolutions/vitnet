use std::io::Cursor;
use vitnet_dgml::{StatsOptions, analyze_stats};

fn options(bytes: usize) -> StatsOptions {
    StatsOptions {
        top: 2,
        memory_limit: 1024 * 1024,
        input_bytes: bytes as u64,
    }
}

#[test]
fn streams_nodes_links_reasons_and_fan_in() {
    let input = br#"<?xml version="1.0"?>
<DirectedGraph xmlns="http://schemas.microsoft.com/vs/2009/dgml">
 <Nodes>
  <Node Id="0" Label="root" />
  <Node Id="1" Label="one" />
  <Node Id="2" Label="two" />
 </Nodes>
 <Links>
  <Link Source="0" Target="2" Reason="A" />
  <Link Source="1" Target="2" Reason="A" />
  <Link Source="0" Target="1" Reason="B &amp; C" />
 </Links>
</DirectedGraph>"#;
    let stats = analyze_stats(Cursor::new(input), options(input.len())).unwrap();
    assert_eq!(stats.schema, "vitnet.dgml-stats.v1");
    assert_eq!(stats.node_count, 3);
    assert_eq!(stats.edge_count, 3);
    assert_eq!(stats.unresolved_endpoints, 0);
    assert_eq!(stats.largest_fan_in[0].node_id, 2);
    assert_eq!(stats.largest_fan_in[0].incoming_edges, 2);
    assert_eq!(stats.reasons[0].name, "A");
    assert_eq!(stats.reasons[0].count, 2);
    assert_eq!(stats.reasons[1].name, "B & C");
    assert_eq!(stats.in_degree_distribution.len(), 3);
    assert_eq!(stats.in_degree_distribution[0].incoming_edges, 0);
    assert_eq!(stats.in_degree_distribution[0].nodes, 1);
    assert_eq!(stats.in_degree_distribution[1].incoming_edges, 1);
    assert_eq!(stats.in_degree_distribution[1].nodes, 1);
    assert_eq!(stats.in_degree_distribution[2].incoming_edges, 2);
    assert_eq!(stats.in_degree_distribution[2].nodes, 1);
}

#[test]
fn reports_duplicates_unresolved_endpoints_and_sparse_ids() {
    let input = br#"<DirectedGraph><Nodes>
<Node Id="5" /><Node Id="5" /><Node Id="9" />
</Nodes><Links><Link Source="5" Target="8" /></Links></DirectedGraph>"#;
    let stats = analyze_stats(Cursor::new(input), options(input.len())).unwrap();
    assert_eq!(stats.node_count, 2);
    assert_eq!(stats.duplicate_node_ids, 1);
    assert_eq!(stats.unresolved_endpoints, 1);
    assert_eq!(stats.max_node_id, Some(9));
}

#[test]
fn rejects_dtds_and_non_numeric_ids() {
    let dtd = br#"<!DOCTYPE x [<!ENTITY e "bad">]><DirectedGraph />"#;
    let error = analyze_stats(Cursor::new(dtd), options(dtd.len())).unwrap_err();
    assert_eq!(error.diagnostic.code, "dgml.xml.external_entity");

    let text = br#"<DirectedGraph><Node Id="name" /></DirectedGraph>"#;
    let error = analyze_stats(Cursor::new(text), options(text.len())).unwrap_err();
    assert_eq!(error.diagnostic.code, "dgml.node_id");
}

#[test]
fn enforces_memory_limit_before_sparse_allocation() {
    let input = br#"<DirectedGraph><Node Id="1000000" /></DirectedGraph>"#;
    let error = analyze_stats(
        Cursor::new(input),
        StatsOptions {
            memory_limit: 1024,
            ..options(input.len())
        },
    )
    .unwrap_err();
    assert_eq!(error.diagnostic.code, "resource.memory_limit");
}
