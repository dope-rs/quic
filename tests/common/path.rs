pub mod peer;
use std::time::{Duration, Instant};

use criterion::{
    BatchSize, BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main,
};
use dope_quic::conn::Connection;
use peer::Pair;
use peer::Receiver as _;

fn queued(len: u64) -> Connection {
    let mut client = Pair::try_default().expect("connected peers").client;
    for token in 0..len {
        client
            .with_scope(|mut scope| scope.path().try_probe(token.to_ne_bytes()))
            .expect("bounded challenge queue");
    }
    client
}

fn path(suite: &mut Criterion) {
    let mut group = suite.benchmark_group("quic_path");
    group.throughput(Throughput::Elements(1));
    for (name, len) in [("inline", 1), ("first_spill", 2), ("resident", 63)] {
        group.bench_function(BenchmarkId::new("admission", name), |bench| {
            bench.iter_batched_ref(
                || queued(len),
                |client| {
                    client
                        .with_scope(|mut scope| {
                            scope.path().try_probe(black_box(len.to_ne_bytes()))
                        })
                        .expect("one remaining challenge slot");
                },
                BatchSize::PerIteration,
            );
        });
    }
    group.bench_function("validated_cache", |bench| {
        let mut pair = Pair::try_default().expect("connected peers");
        let mut token = 0_u64;
        let mut at = Instant::now();
        bench.iter(|| {
            let data = black_box(token.to_ne_bytes());
            token += 1;
            pair.client
                .with_scope(|mut scope| scope.path().try_probe(data))
                .expect("settled challenge queue");
            let start = at;
            for round in 1..=3 {
                at = start + Duration::from_millis(round * 50);
                assert!(
                    pair.server
                        .receive_from(&mut pair.work, &mut pair.client, at)
                        .is_ok(),
                    "challenge ingress"
                );
                assert!(
                    pair.client
                        .receive_from(&mut pair.work, &mut pair.server, at)
                        .is_ok(),
                    "response ingress"
                );
            }
            assert!(pair.client.view().path().has_token(&data));
        });
    });
    group.finish();
}

criterion_group!(benches, path);
criterion_main!(benches);
