use crate::common::peer;
use common::suite::mux::dispatch;
use common::suite::peers::tls;
pub mod common;
use dope_quic::conn::life::accept;
use dope_quic::conn::life::options::Options;
use dope_quic::runtime::mux::builder::Builder;
use std::cell::Cell;
use std::pin::Pin;
use std::time::{Duration, Instant};

use dope::runtime::civil;
use dope_quic::errors;
use dope_quic::proto::epoch;
use peer::Initial;

use common::suite::tokens::{self, Capture, Civil, Count, Unavailable};

#[test]
fn civil_sampled_once() {
    let (signing, key) = peer::raw(0x49).expect("raw identity");
    let cert = signing.server().expect("server TLS");
    let options = (Options::builder()
        .security(|security| security.validation([0x8a; 32]))
        .try_build())
    .expect("fixture configuration must satisfy its declared bounds");
    let auth = accept::Authority::new(cert, options)
        .expect("fixture certificate source and options form a server authority");
    let mut server = Builder::server(Capture::default(), auth)
        .build()
        .expect("fixture authority forms a server router");
    let source = Count {
        samples: Cell::new(0),
        now: Civil::manual().get(),
    };
    let auth = tls::client(key).expect("client TLS");
    let mut client = Builder::client(Capture::default())
        .build()
        .expect("default fixture client router is valid");
    let now = Instant::now();
    Pin::new(&mut client)
        .observe(now, |mut turn| {
            turn.protocol()
                .connect(tokens::SERVER, &auth, Options::default(), vec![0x71; 8])
        })
        .expect("fixture peer, authority, options, and DCID start a connection");
    let mut flight = dispatch::Capture::output(&mut client, now).expect("token output");
    let wire = flight
        .first_mut()
        .and_then(|packet| packet.segments_mut().next())
        .expect("client emits one TLS-bearing Initial")
        .to_vec();
    let mut initial = wire.clone();

    Pin::new(&mut server)
        .observe(Instant::now(), |mut turn| {
            turn.protocol()
                .recv(tokens::CLIENT, &mut initial, epoch::Sample::new(&source))
        })
        .expect("unrouted fixture Initial passes mux ingress");
    assert_eq!(source.samples.get(), 1);
    assert_eq!(server.active_conns(), 1);

    let mut repeat = wire;
    Pin::new(&mut server)
        .observe(Instant::now(), |mut turn| {
            turn.protocol()
                .recv(tokens::CLIENT, &mut repeat, epoch::Sample::new(&source))
        })
        .expect("routed duplicate Initial passes mux ingress");
    assert_eq!(
        source.samples.get(),
        1,
        "a routed Initial must not observe civil time again"
    );

    let mut ordinary = vec![0x40; 64];
    Pin::new(&mut server)
        .observe(Instant::now(), |mut turn| {
            turn.protocol()
                .recv(tokens::CLIENT, &mut ordinary, epoch::Sample::new(&source))
        })
        .expect("ordinary fixture packet passes mux ingress");
    assert_eq!(
        source.samples.get(),
        1,
        "ordinary packet routing must not observe civil time"
    );
    assert_eq!(server.handler().certificates, 0);
}

#[test]
fn unavailable_drops() {
    let (mut server, _) = Capture::server().expect("token server fixture must open");
    let initial = Initial::new(&[0x51; 8], &[0x52; 8], 0).seal(&[0x01]);
    let mut initial = (initial).expect("test precondition");

    let result = Pin::new(&mut server).observe(Instant::now(), |mut turn| {
        turn.protocol().recv(
            tokens::CLIENT,
            &mut initial,
            epoch::Sample::new(Unavailable),
        )
    });
    assert!(matches!(
        result,
        Err(errors::Receive::Civil(civil::Error::BeforeUnixEpoch { delta }))
            if delta == Duration::from_nanos(1)
    ));

    assert_eq!(server.active_conns(), 0);
    assert_eq!(Capture::drain(&mut server).expect("token drain"), 0);
    assert_eq!(server.handler().certificates, 0);
}

#[test]
fn bad_domain_drops() {
    let civil = Civil::manual();
    let (mut server, _) = Capture::server().expect("token server fixture must open");
    let initial = Initial::new(&[0x61; 8], &[0x62; 8], 0)
        .token(&[0x5a; 23])
        .seal(&[0x01]);
    let mut initial = (initial).expect("test precondition");

    Pin::new(&mut server)
        .observe(Instant::now(), |mut turn| {
            turn.protocol().recv(
                tokens::CLIENT,
                &mut initial,
                epoch::Sample::new(Civil(&civil)),
            )
        })
        .expect("malformed token domain is a closed admission outcome");

    assert_eq!(server.active_conns(), 0);
    assert_eq!(Capture::drain(&mut server).expect("token drain"), 0);
    assert_eq!(server.handler().certificates, 0);
}
