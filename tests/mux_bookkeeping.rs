pub mod common;
use common::suite::mux::{Ignore, output::SERVER};
use common::suite::peers::tls;
use dope_quic::conn::life::options::Options;
use std::hint::black_box;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::{Duration, Instant};

use dope_quic::proto::{cid, param};
use dope_quic::runtime::mux::builder;
use dope_test::alloc::Tracker;

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();

#[test]
fn mux_controls_no_alloc() {
    let limits = (builder::Plan::try_new(1, 8, 16 << 10)).expect("control fixture limits");
    let mut owned = (builder::Builder::client(Ignore).limits(limits).build())
        .expect("owned client mux allocation");
    let mut pooled = (builder::Builder::client_pool(Ignore).limits(limits).build())
        .expect("pooled client mux allocation");
    let now = Instant::now();

    let span = Tracker::begin();
    black_box(Pin::new(&mut owned).config());
    black_box(Pin::new(&mut owned).output());
    Pin::new(&mut owned).observe(now, |mut turn| {
        black_box(turn.deadline());
        black_box(turn.protocol());
        black_box(turn.output());
        black_box(turn.lifecycle());
        let mut rotation = turn.plan_cid(cid::Rotation::disabled());
        black_box(turn.maintain_cid(&mut rotation));
    });
    black_box(Pin::new(&mut pooled).config());
    black_box(Pin::new(&mut pooled).output());
    Pin::new(&mut pooled).observe(now, |mut turn| {
        black_box(turn.deadline());
        black_box(turn.protocol());
        black_box(turn.output());
        black_box(turn.lifecycle());
        let mut rotation = turn.plan_cid(cid::Rotation::disabled());
        black_box(turn.maintain_cid(&mut rotation));
    });
    let activity = span.finish();

    assert_eq!(activity.allocations, 0);
}

#[test]
fn conn_scope_no_alloc() {
    let now = Instant::now();
    let limits = (builder::Plan::try_new(1, 8, 16 << 10)).expect("bookkeeping fixture limits");
    let mut mux = builder::Builder::client(Ignore)
        .limits(limits)
        .build()
        .expect("client mux allocation");
    let handle = (Pin::new(&mut mux).observe(now, |mut turn| {
        turn.protocol().connect(
            SERVER,
            &tls::client([7; 32]).expect("client TLS authority"),
            Options::default(),
            vec![0x43; 8],
        )
    }))
    .expect("fixed peer connection");
    assert!(
        Pin::new(&mut mux)
            .observe(now, |mut turn| {
                turn.protocol().with_conn(handle, |scope| {
                    black_box(scope.view().lifecycle().is_opening())
                })
            })
            .is_ok(),
        "the newly opened connection must remain addressable"
    );

    let span = Tracker::begin();
    for _ in 0..4096 {
        assert!(
            Pin::new(&mut mux)
                .observe(now, |mut turn| {
                    turn.protocol().with_conn(handle, |scope| {
                        black_box(scope.view().lifecycle().is_opening())
                    })
                })
                .is_ok(),
            "the measured connection must remain addressable"
        );
    }
    let activity = span.finish();

    assert_eq!(activity.allocations, 0);
}

/// RFC 9000 requires the effective idle timeout to be at least 3×PTO, so the
/// first deadline can be a loss timer rather than the configured 1ms idle timer.
#[test]
fn bookkeeping_no_alloc() {
    let now = Instant::now();
    let params = param::Set::builder()
        .idle_ms(1)
        .try_build()
        .expect("fixture transport parameters");
    let config =
        Options::try_from(params).expect("fixture configuration must satisfy its declared bounds");
    let limits = (builder::Plan::try_new(1, 8, 16 << 10)).expect("bookkeeping fixture limits");
    let mut mux = builder::Builder::client(Ignore)
        .limits(limits)
        .build()
        .expect("client mux allocation");
    assert!(
        Pin::new(&mut mux)
            .observe(now, |mut turn| {
                turn.protocol().connect(
                    SERVER,
                    &tls::client([7; 32]).expect("client TLS authority"),
                    config,
                    vec![0x42; 8],
                )
            })
            .is_ok(),
        "the fixed peer, key, options, and CID must open a connection"
    );
    Pin::new(&mut mux).observe(Instant::now(), |mut turn| {
        assert!(
            turn.output().drive().is_ok(),
            "fixture mux connection must admit its initial output"
        );
        black_box(turn.output().drain().count());
    });
    let deadline = (Pin::new(&mut mux).observe(now, |turn| turn.deadline()))
        .expect("opened connection deadline");

    let span = Tracker::begin();
    for _ in 0..4096 {
        black_box(Pin::new(&mut mux).observe(now, |turn| turn.deadline()));
        Pin::new(&mut mux).observe(now, |mut turn| {
            let count = (turn.output().drive())
                .expect("fixture mux connection must admit bookkeeping output");
            black_box(count);
        });
    }
    Pin::new(&mut mux).observe(deadline + Duration::from_secs(5), |mut turn| {
        assert!(
            turn.output().drive().is_ok(),
            "expired fixture connection must close without admission failure"
        )
    });
    let activity = span.finish();

    assert_eq!(mux.active_conns(), 0);
    assert_eq!(activity.allocations, 0);
}

#[test]
fn deadline_advances_due() {
    let first = SERVER;
    let second = SocketAddr::from(([10, 0, 0, 3], 443));
    let now = Instant::now();
    let limits = (builder::Plan::try_new(2, 8, 16 << 10)).expect("bookkeeping fixture limits");
    let mut mux = builder::Builder::client(Ignore)
        .limits(limits)
        .build()
        .expect("client mux allocation");
    assert!(
        Pin::new(&mut mux)
            .observe(now, |mut turn| {
                turn.protocol().connect(
                    first,
                    &tls::client([1; 32]).expect("first TLS authority"),
                    Options::default(),
                    vec![1; 8],
                )
            })
            .is_ok(),
        "the first fixed peer and CID must open a connection"
    );
    Pin::new(&mut mux).observe(now, |mut turn| {
        assert!(
            turn.output().drive().is_ok(),
            "first fixture connection must admit initial output"
        );
        black_box(turn.output().drain().count());
    });
    let result = Pin::new(&mut mux).observe(now + Duration::from_millis(100), |mut turn| {
        turn.protocol().connect(
            second,
            &tls::client([2; 32]).expect("second TLS authority"),
            Options::default(),
            vec![2; 8],
        )
    });
    assert!(
        result.is_ok(),
        "the second fixed peer and CID must open a connection"
    );
    let driven = now + Duration::from_millis(100);
    Pin::new(&mut mux).observe(driven, |mut turn| {
        assert!(
            turn.output().drive().is_ok(),
            "second fixture connection must admit initial output"
        );
        black_box(turn.output().drain().count());
    });

    let deadline = (Pin::new(&mut mux).observe(now, |turn| turn.deadline()))
        .expect("two opened connections must have a deadline");
    let dests = Pin::new(&mut mux).observe(deadline + Duration::from_micros(1), |mut turn| {
        assert!(
            turn.output().drive().is_ok(),
            "due fixture connection must admit deadline output"
        );
        turn.output()
            .drain()
            .map(|outgoing| outgoing.addr())
            .collect::<Vec<_>>()
    });

    assert!(!dests.is_empty());
    assert!(dests.iter().all(|addr| *addr == first));
}
