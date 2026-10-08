use criterion::{Criterion, criterion_group, criterion_main};
use std::fmt::Write as _;
use std::hint::black_box;
use std::time::Duration;
use vitnet_dgml::{
    GraphSession, IncomingOptions, IndexControl, IndexOptions, WhyOptions, build_index,
};

fn queries(criterion: &mut Criterion) {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("graph.xml");
    let mut graph = String::from("<DirectedGraph><Nodes>");
    for id in 0..=10_001 {
        write!(&mut graph, r#"<Node Id="{id}" Label="node-{id}"/>"#).unwrap();
    }
    graph.push_str("</Nodes><Links>");
    for id in 1..=10_000 {
        write!(&mut graph, r#"<Link Source="0" Target="{id}" Reason=""/><Link Source="{id}" Target="10001" Reason="call"/>"#).unwrap();
    }
    graph.push_str("</Links></DirectedGraph>");
    std::fs::write(&input, graph).unwrap();
    let index = build_index(
        &input,
        &IndexOptions {
            cache_root: directory.path().join("cache"),
            memory_limit: 64 << 20,
            selected_entry: None,
            strict_hash: false,
            control: IndexControl::default(),
        },
    )
    .unwrap();
    let mut session = GraphSession::open(&index.index_directory, 64 << 20).unwrap();
    let incoming = IncomingOptions {
        limit: 10_000,
        preview_bytes: 128,
        ..Default::default()
    };
    assert_eq!(
        session.incoming(10_001, &incoming).unwrap().edges.len(),
        10_000
    );
    criterion.bench_function("incoming_10000", |bench| {
        bench.iter(|| black_box(session.incoming(10_001, &incoming).unwrap()));
    });
    let why = WhyOptions {
        max_visited: 11_000,
        max_edges: 12_000,
        ..Default::default()
    };
    let witness = session.why(10_001, &why).unwrap();
    assert_eq!(witness.paths.len(), 1);
    assert_eq!(witness.examined_edges, 20_000_u64.min(why.max_edges));
    criterion.bench_function("why_fan_in_10000", |bench| {
        bench.iter(|| black_box(session.why(10_001, &why).unwrap()));
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20)
        .warm_up_time(Duration::from_millis(200))
        .measurement_time(Duration::from_secs(2));
    targets = queries
}
criterion_main!(benches);
