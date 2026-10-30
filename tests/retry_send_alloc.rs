use crate::common::peer;
pub mod common;
use common::suite::{mux::dispatch, retry::Capture};

use dope_quic::conn::life::options::Options;
use dope_quic::runtime::mux::builder::Plan;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Instant;

use dope_quic::proto::epoch;
use dope_quic::wire::packet::{self, QUIC_V1};
use dope_test::alloc::Tracker;
use long::{initial, retry};
use packet::long;

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();

#[test]
fn control_reuses_alloc() {
    let options = (Options::builder()
        .security(|security| security.retry([0xa5; 32]))
        .try_build())
    .expect("fixture connection options");
    let mut mux = dispatch::Capture::server(
        Capture { certificates: 0 },
        peer::raw(0x39)
            .expect("fixture server identity")
            .0
            .server()
            .expect("fixture server TLS configuration"),
        options,
        Plan::standard(),
    )
    .expect("fixture server");
    let orig = [0x11; 8];
    let peer = [0x22; 8];
    let mut initial = initial::Header {
        version: QUIC_V1,
        dcid: orig.to_vec(),
        scid: peer.to_vec(),
        token: Vec::new(),
        packet_number: 0,
        pn_len: 1,
    }
    .encode(84)
    .expect("encode Initial")
    .as_bytes()
    .to_vec();
    initial.resize(initial.len() + 100, 0);
    let source: SocketAddr = "127.0.0.1:55001".parse().expect("source address");

    assert!(initial.len() < 1200);
    let sample = Tracker::begin();
    let received = Pin::new(&mut mux).observe(Instant::now(), |mut turn| {
        turn.protocol()
            .recv(source, &mut initial, epoch::WALL_CLOCK)
    });
    let activity = sample.finish();

    assert!(received.is_ok(), "discard undersized Initial");
    assert_eq!(activity.allocations, 0);
    assert_eq!(mux.active_conns(), 0);
    assert!(
        Capture::take(&mut mux, Instant::now())
            .expect("retry take")
            .is_none()
    );

    initial.resize(1200, 0);

    let sample = Tracker::begin();
    let received = Pin::new(&mut mux).observe(Instant::now(), |mut turn| {
        turn.protocol()
            .recv(source, &mut initial, epoch::WALL_CLOCK)
    });
    let activity = sample.finish();

    assert!(received.is_ok(), "receive Initial");
    assert_eq!(activity.allocations, 1, "cold Retry");
    let outgoing = Capture::take(&mut mux, Instant::now())
        .expect("retry take")
        .expect("one Retry");
    assert!(outgoing.is_suffix());
    let retry = retry::Ref::decode(outgoing.payload()).expect("decode Retry");
    assert!(retry.dcid() == peer);
    let ptr = outgoing.payload().as_ptr();
    Pin::new(&mut mux).output().recycle(outgoing);

    let sample = Tracker::begin();
    let received = Pin::new(&mut mux).observe(Instant::now(), |mut turn| {
        turn.protocol()
            .recv(source, &mut initial, epoch::WALL_CLOCK)
    });
    let activity = sample.finish();

    assert!(received.is_ok(), "receive second Initial");
    assert_eq!(activity.allocations, 0, "warm Retry");
    let outgoing = Capture::take(&mut mux, Instant::now())
        .expect("retry take")
        .expect("second Retry");
    assert!(outgoing.is_suffix());
    assert_eq!(outgoing.payload().as_ptr(), ptr);

    let options = (Options::builder()
        .security(|security| security.reset(Some([0x5a; 32])))
        .try_build())
    .expect("fixture connection options");
    let mut reset = dispatch::Capture::server(
        Capture { certificates: 0 },
        peer::raw(0x49)
            .expect("fixture server identity")
            .0
            .server()
            .expect("fixture server TLS configuration"),
        options,
        Plan::standard(),
    )
    .expect("fixture server");
    let mut trigger = vec![0x40; 64];

    let sample = Tracker::begin();
    let received = Pin::new(&mut reset).observe(Instant::now(), |mut turn| {
        turn.protocol()
            .recv(source, &mut trigger, epoch::WALL_CLOCK)
    });
    let activity = sample.finish();

    assert!(received.is_ok(), "receive unknown packet");
    assert_eq!(activity.allocations, 1, "cold stateless reset");
    let outgoing = Capture::take(&mut reset, Instant::now())
        .expect("retry take")
        .expect("one reset");
    assert!(!outgoing.is_suffix() && !outgoing.is_segmented());
    let ptr = outgoing.payload().as_ptr();
    Pin::new(&mut reset).output().recycle(outgoing);

    let sample = Tracker::begin();
    let received = Pin::new(&mut reset).observe(Instant::now(), |mut turn| {
        turn.protocol()
            .recv(source, &mut trigger, epoch::WALL_CLOCK)
    });
    let activity = sample.finish();

    assert!(received.is_ok(), "receive second unknown packet");
    assert_eq!(activity.allocations, 0, "warm stateless reset");
    let outgoing = Capture::take(&mut reset, Instant::now())
        .expect("retry take")
        .expect("second reset");
    assert!(!outgoing.is_suffix() && !outgoing.is_segmented());
    assert_eq!(outgoing.payload().as_ptr(), ptr);
    assert_eq!(mux.handler().certificates, 0);
    assert_eq!(reset.handler().certificates, 0);
}
