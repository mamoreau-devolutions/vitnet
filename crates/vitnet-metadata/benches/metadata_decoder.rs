use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use vitnet_metadata::{AnalysisOptions, StreamingDecoder, analyze_stream};

fn fixture(records: u32) -> Vec<u8> {
    let mut bytes = b"Handle, Kind, Name, Children\n".to_vec();
    for index in 0..records {
        bytes.extend_from_slice(
            format!("{index:08x}, ConstantStringValue, \"value,{index}\\\"line\", \"\"\n")
                .as_bytes(),
        );
    }
    bytes
}

fn decoder_benchmark(criterion: &mut Criterion) {
    let input = fixture(10_000);
    let mut group = criterion.benchmark_group("metadata");
    group.throughput(Throughput::Bytes(input.len() as u64));
    group.bench_function("decode_and_aggregate_10k", |bencher| {
        bencher.iter(|| {
            let analysis = analyze_stream(
                StreamingDecoder::new(black_box(input.as_slice()), 64 * 1024, true),
                AnalysisOptions::default(),
                true,
                64 * 1024 * 1024,
            )
            .unwrap();
            black_box(analysis);
        });
    });
    group.finish();
}

criterion_group!(benches, decoder_benchmark);
criterion_main!(benches);
