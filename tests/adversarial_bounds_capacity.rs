use dope_quic::conn::life::options::Options;
use dope_quic::runtime::mux::builder::Plan;
use std::time::Instant;

use dope_quic::conn::Error;
use dope_quic::conn::life::options::builder;
use dope_quic::proto::early::ReplayCap;
use dope_quic::runtime::mux;

pub mod common;
use common::suite::peers::bounds::Server;

#[test]
fn invalid_limits() {
    assert!(matches!(
        Options::builder()
            .transport(|transport| transport.max_pmtu(u64::MAX))
            .try_build(),
        Err(builder::Invalid::Pmtu {
            actual,
            minimum: 1_200,
            maximum: 65_527,
        }) if actual == u64::MAX
    ));
    assert!(matches!(
        Options::builder()
            .streams(|streams| streams.local_bidi(65_537))
            .try_build(),
        Err(builder::Invalid::LocalBidi {
            actual: 65_537,
            minimum: 0,
            maximum: 65_536,
        })
    ));
    assert!(matches!(
        Options::builder()
            .streams(|streams| streams.local_uni(65_537))
            .try_build(),
        Err(builder::Invalid::LocalUni {
            actual: 65_537,
            minimum: 0,
            maximum: 65_536,
        })
    ));
    assert!(matches!(
        Options::builder()
            .streams(|streams| streams.events(usize::MAX))
            .try_build(),
        Err(builder::Invalid::StreamEvents {
            actual,
            minimum: 1,
            maximum: 65_536,
        }) if actual == usize::MAX
    ));
}

#[test]
fn udp_payload_bound() {
    let Server {
        conn: mut server,
        mut work,
    } = Server::try_new().expect("adversarial fixture server must open");
    let mut large = vec![0; 65_528];
    assert!(matches!(
        server.with_scope(|mut scope| scope.input(&mut work).recv_packet(
            &mut large,
            Instant::now(),
            |_: &rustls::Error| {}
        )),
        Err(Error::PacketCeiling)
    ));
}

#[test]
fn stream_capacity_bound() {
    assert!(matches!(
        Options::builder()
            .streams(|streams| streams.local_uni(usize::MAX))
            .try_build(),
        Err(builder::Invalid::LocalUni {
            actual,
            minimum: 0,
            maximum: 65_536,
        }) if actual == usize::MAX
    ));
    assert!(matches!(
        Options::builder()
            .streams(|streams| streams.local_bidi(usize::MAX))
            .try_build(),
        Err(builder::Invalid::LocalBidi {
            actual,
            minimum: 0,
            maximum: 65_536,
        }) if actual == usize::MAX
    ));
}

#[test]
fn allocation_bounds() {
    assert!(ReplayCap::new(usize::MAX).is_none());
    assert!(matches!(
        Plan::try_new(0, 1, 1),
        Err(mux::builder::Error::Connections {
            got: 0,
            max: 65_536,
        })
    ));
    assert!(matches!(
        Plan::try_new(1, usize::MAX, 1),
        Err(mux::builder::Error::Packets { got, max: 65_536 }) if got == usize::MAX
    ));
    assert!(matches!(
        Plan::try_new(1, 1, usize::MAX),
        Err(mux::builder::Error::Bytes {
            got,
            max: 1_073_741_824,
        }) if got == usize::MAX
    ));
}
