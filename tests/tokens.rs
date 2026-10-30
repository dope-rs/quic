use common::suite::{
    mux::{Reject, dispatch},
    peers::Error,
};
pub mod common;
use dope_quic::conn::life::{options::Options, tls::clients};
use dope_quic::runtime::{
    mux::builder::Builder,
    routing::{Plain, Shard},
};
use dope_tls::config;
use rustls::pki_types::ServerName;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::num::NonZero;
use std::pin::Pin;
use std::time::{Duration, Instant};

use dope_quic::errors::Connect;
use dope_quic::proto::epoch;
use dope_quic::wire::packet::{cid, long};
use long::initial;

use common::suite::tokens::{self, Capture, Civil};

#[test]
fn retains_until_install() {
    let civil = Civil::manual();
    let (mut server, key) = Capture::server().expect("token server");
    let (first, saved) = Capture::issue(
        &mut server,
        key,
        tokens::FIRST_DCID,
        tokens::CLIENT,
        Civil(&civil),
    )
    .expect("token issue");
    let saved = saved.expect("reconnect capability");
    drop(first);
    let pool = clients::Pool::new(
        saved.auth().try_clone().expect("retained authority"),
        NonZero::<usize>::MIN,
    );
    let id = cid::Id::try_from([0x52; 8]).expect("connection ID");
    let active = pool
        .connect::<0>(id, id, Options::default(), Plain)
        .expect("one active handshake");
    let failure = pool
        .reconnect::<0>(id, id, Options::default(), saved, Plain)
        .err()
        .expect("full handshake pool");
    assert!(matches!(failure.error(), Connect::Capacity));
    let saved = failure.into_parts().1.expect("capacity retains capability");
    drop(active);

    let mut rejected = Builder::client(Reject {
        attempts: Vec::new(),
        closed: Vec::new(),
        certificates: 0,
    })
    .build()
    .expect("rejecting client mux");
    let failure = Pin::new(&mut rejected)
        .observe(Instant::now(), |mut turn| {
            turn.protocol().reconnect(Options::default(), saved, Plain)
        })
        .expect_err("application rejects installation");
    let (error, saved) = failure.into_parts();
    assert!(matches!(error, Connect::ApplicationRejected));
    assert!(saved.is_none());
    assert_eq!(rejected.active_conns(), 0);
}

#[test]
fn skips_retry() {
    let civil = Civil::manual();
    let (mut server, key) = Capture::server().expect("token server fixture must open");
    let (mut first, resume) = Capture::issue(
        &mut server,
        key,
        tokens::FIRST_DCID,
        tokens::CLIENT,
        Civil(&civil),
    )
    .expect("token issue");
    let resume = resume.expect("saved reconnect capability");
    assert_eq!(resume.peer(), tokens::SERVER);
    assert_eq!(server.active_conns(), 1);

    let result = Pin::new(&mut first).observe(Instant::now(), |mut turn| {
        turn.protocol().reconnect(Options::default(), resume, Plain)
    });
    let failure = result.expect_err("occupied client rejects a second connection");
    assert!(matches!(failure.error(), Connect::Capacity));
    let (_, resume) = failure.into_parts();
    let resume = resume.expect("pre-install capacity failure retains the capability");
    drop(first);

    let foreign = clients::Authority::try_new(
        config::raw::Identity::client(key).expect("same server verifier"),
        ServerName::try_from(String::from("localhost")).expect("same owned server name"),
    )
    .expect("client authority");
    let id = cid::Id::try_from([0x51; 8]).expect("connection ID");
    let failure = foreign
        .reconnect::<0>(id, id, Options::default(), resume, Plain)
        .err()
        .expect("a separately owned policy must reject the saved capability");
    assert!(matches!(failure.error(), Connect::AuthorityMismatch));
    let (_, resume) = failure.into_parts();
    let resume = resume.expect("authority rejection retains the capability");

    let mut second = Builder::client(Capture::default())
        .build()
        .expect("reconnect router");
    let failure = Pin::new(&mut second)
        .observe(Instant::now(), |mut turn| {
            turn.protocol()
                .reconnect(Options::default(), resume, Shard::from_index(1))
        })
        .expect_err("a different route must reject the saved capability");
    assert!(matches!(failure.error(), Connect::InvalidConfig));
    let (_, resume) = failure.into_parts();
    let resume = resume.expect("route rejection retains the capability");
    Pin::new(&mut second)
        .observe(Instant::now(), |mut turn| {
            turn.protocol().reconnect(Options::default(), resume, Plain)
        })
        .as_ref()
        .map_err(|failure| failure.error())
        .expect("retained policy reconnects after its source router drops");
    assert!(
        Capture::relay(&mut second, &mut server, tokens::CLIENT, Civil(&civil))
            .expect("token relay")
            > 0
    );
    assert_eq!(
        server.active_conns(),
        2,
        "a valid NEW_TOKEN admits the Initial without a Retry round trip"
    );
    let &handle =
        (server.handler().handles.get(1)).expect("reconnect must emit the second accepted handle");
    assert!(
        server
            .conn(handle)
            .expect("accepted reconnect handle remains installed")
            .view()
            .path()
            .is_valid()
    );
}

#[test]
fn endpoint_is_bound() {
    let civil = Civil::manual();
    let (mut server, key) = Capture::server().expect("token server fixture must open");
    let (_, resume) = Capture::issue(
        &mut server,
        key,
        tokens::FIRST_DCID,
        tokens::CLIENT,
        Civil(&civil),
    )
    .expect("token issue");
    let resume = resume.expect("saved reconnect capability");
    assert_eq!(resume.peer(), tokens::SERVER);
    let active = server.active_conns();
    Capture::drain(&mut server).expect("token drain");
    let result = Capture::client(resume);
    result.as_ref().map_err(Error::cause).expect("setup");
    let mut next = result.ok().expect("token reconnect");
    let changed: SocketAddr = "10.0.0.1:50001"
        .parse()
        .expect("fixture changed endpoint is a valid socket address");

    assert!(
        Capture::relay(&mut next, &mut server, changed, Civil(&civil)).expect("token relay") > 0
    );
    assert_eq!(server.active_conns(), active);
    assert!(
        Capture::drain(&mut server).expect("token drain") > 0,
        "an endpoint mismatch must require a fresh Retry proof"
    );
}

#[test]
fn ipv6_scope_is_bound() {
    let civil = Civil::manual();
    let (mut server, key) = Capture::server().expect("token server fixture must open");
    let peer = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 50_000, 7, 3));
    let (_, resume) = Capture::issue(&mut server, key, tokens::FIRST_DCID, peer, Civil(&civil))
        .expect("token issue");
    let resume = resume.expect("saved reconnect capability");
    assert_eq!(resume.peer(), tokens::SERVER);
    let active = server.active_conns();
    Capture::drain(&mut server).expect("token drain");
    let result = Capture::client(resume);
    result.as_ref().map_err(Error::cause).expect("setup");
    let mut next = result.ok().expect("token reconnect");
    let changed = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 50_000, 7, 4));

    assert!(
        Capture::relay(&mut next, &mut server, changed, Civil(&civil)).expect("token relay") > 0
    );
    assert_eq!(server.active_conns(), active);
    assert!(Capture::drain(&mut server).expect("token drain") > 0);
    assert_eq!(server.handler().certificates, 0);
}

#[test]
fn forgery_never_validates() {
    let civil = Civil::manual();
    let (mut server, key) = Capture::server().expect("token server fixture must open");
    let (_, resume) = Capture::issue(
        &mut server,
        key,
        tokens::FIRST_DCID,
        tokens::CLIENT,
        Civil(&civil),
    )
    .expect("token issue");
    let resume = resume.expect("saved reconnect capability");
    assert_eq!(resume.peer(), tokens::SERVER);
    let active = server.active_conns();
    Capture::drain(&mut server).expect("token drain");
    let result = Capture::client(resume);
    result.as_ref().map_err(Error::cause).expect("setup");
    let mut next = result.ok().expect("token reconnect");
    let now = Instant::now();
    let packets = dispatch::Capture::output(&mut next, now).expect("token output");
    assert!(!packets.is_empty());
    Pin::new(&mut server).observe(now, |mut turn| {
        for mut packet in packets {
            for segment in packet.segments_mut() {
                let (start, len) = {
                    let prefix = initial::Prefix::decode(segment)
                        .expect("fixture client emits a decodable Initial prefix");
                    (
                        prefix.token.as_ptr() as usize - segment.as_ptr() as usize,
                        prefix.token.len(),
                    )
                };
                assert_eq!(len, 24);
                segment[start + len - 1] ^= 1;
                turn.protocol()
                    .recv(tokens::CLIENT, segment, epoch::Sample::new(Civil(&civil)))
                    .expect("forged token is a valid packet with invalid authentication");
            }
        }
        turn.output()
            .drive()
            .expect("forged-token rejection output must fit fixture capacity");
    });

    assert_eq!(server.active_conns(), active);
    assert!(Capture::drain(&mut server).expect("token drain") > 0);
    assert_eq!(server.handler().certificates, 0);
}

#[test]
fn expiry_is_exact() {
    let civil = Civil::manual();
    let start = civil.get();
    let (mut server, key) = Capture::server().expect("token server fixture must open");
    let (_, valid) = Capture::issue(
        &mut server,
        key,
        tokens::FIRST_DCID,
        tokens::CLIENT,
        Civil(&civil),
    )
    .expect("token issue");
    let valid = valid.expect("saved reconnect capability");
    assert_eq!(valid.peer(), tokens::SERVER);
    let (_, expired) = Capture::issue(&mut server, key, [0x42; 8], tokens::CLIENT, Civil(&civil))
        .expect("token issue");
    let expired = expired.expect("saved reconnect capability");
    assert_eq!(expired.peer(), tokens::SERVER);

    civil.set(
        start
            .try_add(tokens::TTL - Duration::from_millis(1))
            .expect("one millisecond before token TTL fits civil time"),
    );
    let active = server.active_conns();
    let result = Capture::client(valid);
    result.as_ref().map_err(Error::cause).expect("setup");
    let mut client = result.ok().expect("token reconnect");
    assert!(
        Capture::relay(&mut client, &mut server, tokens::CLIENT, Civil(&civil))
            .expect("token relay")
            > 0
    );
    assert_eq!(server.active_conns(), active + 1);

    Capture::drain(&mut server).expect("token drain");
    civil.set(
        start
            .try_add(tokens::TTL)
            .expect("exact token TTL fits civil time"),
    );
    let active = server.active_conns();
    let result = Capture::client(expired);
    result.as_ref().map_err(Error::cause).expect("setup");
    let mut client = result.ok().expect("token reconnect");
    assert!(
        Capture::relay(&mut client, &mut server, tokens::CLIENT, Civil(&civil))
            .expect("token relay")
            > 0
    );
    assert_eq!(server.active_conns(), active);
    assert!(Capture::drain(&mut server).expect("token drain") > 0);
}
