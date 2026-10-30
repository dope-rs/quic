use crate::common::peer;
pub mod common;

use crate::common::suite::mux::dispatch::{CLIENT, Capture, SERVER};
use crate::common::suite::peers::packet::Session;
use crate::common::suite::peers::tls::{Kind, Rejected};
use dope_quic::conn::life::tls::clients;
use dope_quic::conn::{
    self,
    life::{accept, options::Options},
    wire::Handshake,
};
use dope_quic::errors;
use dope_quic::proto::{epoch, param};
use dope_quic::runtime::mux::{
    builder::{Builder, Plan},
    handler,
};
use dope_tls::config;
use o3::buffer::storage;
use rustls::pki_types::ServerName;
use rustls::{AlertDescription, Error};
use std::{
    env,
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    pin::Pin,
    time::Instant,
};

fn authenticate<const RELEASE: bool, F>(base: &Path, kind: Kind, corrupt: bool, check: F)
where
    F: FnMut(Result<(), &Error>) + Unpin,
    Rejected<RELEASE, F>: handler::Handler<0, Vec<u8>, storage::Shared, Connection = ()>,
{
    let params = param::Set::builder()
        .idle_ms(30_000)
        .try_build()
        .expect("fixture parameters");
    let mut cleanup = None;
    let result = kind.configs(base, |result| cleanup = Some(result));
    result
        .as_ref()
        .map_err(|error| (error, &cleanup))
        .expect("fixture certificate construction");
    let (client, server) = result.expect("admitted identities");
    if let Some(cleanup) = cleanup {
        cleanup.expect("fixture certificate cleanup");
    }
    let mut peer = Session::try_new(client, &params).expect("independent TLS client");
    let options = Options::try_from(params).expect("fixture options");
    let auth = accept::Authority::new(server, options).expect("mutual-auth server authority");
    let mut router = Builder::server(Rejected::<RELEASE, F>::new(kind, check), auth)
        .build()
        .expect("certificate-test router");
    let address = SocketAddr::from(([127, 0, 0, 1], 31_421));
    let now = Instant::now();
    Pin::new(&mut router)
        .observe(now, |mut turn| {
            turn.protocol().recv(
                address,
                &mut peer.initial().expect("client Initial"),
                epoch::WALL_CLOCK,
            )
        })
        .expect("server receives Initial");
    assert_eq!(router.active_conns(), 1);
    let handle = router.sole().expect("one admitted client identity");
    assert_eq!(router.handler().certificates, 0);
    let outgoing: Vec<_> = Pin::new(&mut router).observe(now, |mut turn| {
        turn.output().drive().expect("server handshake output");
        turn.output().drain().collect()
    });
    assert!(!outgoing.is_empty());
    for mut outgoing in outgoing {
        for packet in outgoing.segments_mut() {
            let _ = peer
                .receive(packet)
                .expect("independent peer receives server flight");
        }
        Pin::new(&mut router).output().recycle(outgoing);
    }
    let mut finish = peer
        .finish(corrupt.then_some(kind.oid()))
        .expect("client certificate flight");
    let mut replay = finish.clone();
    let result = Pin::new(&mut router).observe(now, |mut turn| {
        turn.protocol()
            .recv(address, &mut finish, epoch::WALL_CLOCK)
    });
    if !corrupt {
        result.expect("valid client certificate and Finished");
        assert_eq!(router.handler().certificates, 0);
        assert!(
            router
                .conn(handle)
                .expect("authenticated connection")
                .view()
                .lifecycle()
                .is_ready()
        );
        return;
    }
    assert!(
        matches!(
            &result,
            Err(errors::Receive::Packet(conn::Error::Handshake(Handshake {
                error: Error::InvalidCertificate(cause),
                alert,
            }))) if cause == &kind.error() && alert == &Some(kind.alert())
        ),
        "{result:?}"
    );
    assert_eq!(router.handler().certificates, 1);
    assert_eq!(router.handler().released, 0);
    assert!(
        router
            .conn(handle)
            .expect("rejected connection remains scoped until retirement")
            .view()
            .lifecycle()
            .is_closing()
    );
    let replay = Pin::new(&mut router).observe(now, |mut turn| {
        turn.protocol()
            .recv(address, &mut replay, epoch::WALL_CLOCK)
    });
    replay.expect("closing connection discards authenticated replay without reentering TLS");
    assert_eq!(
        router.handler().certificates,
        1,
        "a failed TLS owner must not replay its borrowed cause"
    );
    assert_eq!(
        Pin::new(&mut router).observe(now, |turn| turn.seal().close_all()),
        1
    );
    assert_eq!(router.active_conns(), 0);
    assert_eq!(router.handler().released, 0);
}

#[test]
fn schedules_initial_close() {
    let (signing, key) = peer::raw(0x60).expect("server identity");
    let mut config = signing.server().expect("server TLS configuration");
    config.alpn_protocols = vec![b"h3".to_vec()];
    let mut server = Capture::server(
        Capture::default(),
        config,
        Options::default(),
        Plan::standard(),
    )
    .expect("fixture server router");
    let mut client = Builder::client(Capture::default())
        .build()
        .expect("client router");
    let mut config = config::raw::Identity::client(key).expect("pinned server configuration");
    config.alpn_protocols = vec![b"wrong".to_vec()];
    let auth =
        clients::Authority::try_new(config, ServerName::IpAddress(Ipv4Addr::LOCALHOST.into()))
            .expect("client authority");
    let now = Instant::now();
    Pin::new(&mut client)
        .observe(now, |mut turn| {
            turn.protocol()
                .connect(SERVER, &auth, Options::default(), vec![0x42; 8])
        })
        .expect("fixture client connection");
    let mut flights = Capture::output(&mut client, now).expect("client Initial output");
    let first = flights.first_mut().expect("Initial flight");
    let packet = first.segments_mut().next().expect("Initial packet");
    let result = Pin::new(&mut server).observe(now, |mut turn| {
        turn.protocol().recv(CLIENT, packet, epoch::WALL_CLOCK)
    });
    assert!(matches!(
        result,
        Err(errors::Receive::Packet(conn::Error::Handshake(Handshake {
            error: Error::NoApplicationProtocol,
            alert: Some(AlertDescription::NoApplicationProtocol),
        })))
    ));
    assert_eq!(
        Pin::new(&mut server).observe(now, |turn| turn.deadline()),
        Some(now)
    );
    assert!(
        !Capture::output(&mut server, now)
            .expect("server Initial close output")
            .is_empty()
    );
    assert_eq!(server.active_conns(), 0);
    for router in [&client, &server] {
        assert!(
            router
                .handler()
                .events
                .borrow()
                .owners
                .iter()
                .all(|(owner, handle)| owner == handle)
        );
    }
}

#[test]
fn raw_without_release() {
    let base = env::temp_dir();
    authenticate::<false, _>(&base, Kind::Raw, true, |result| {
        result.expect("exact raw certificate diagnostic")
    });
}

#[test]
fn raw_with_release() {
    let base = env::temp_dir();
    authenticate::<true, _>(&base, Kind::Raw, true, |result| {
        result.expect("exact raw certificate diagnostic")
    });
}

#[test]
fn x509_without_release() {
    let base = env::temp_dir();
    authenticate::<false, _>(&base, Kind::X509, true, |result| {
        result.expect("exact X.509 certificate diagnostic")
    });
}

#[test]
fn x509_with_release() {
    let base = env::temp_dir();
    authenticate::<true, _>(&base, Kind::X509, true, |result| {
        result.expect("exact X.509 certificate diagnostic")
    });
}

#[test]
fn x509_client_accepted() {
    let base = env::temp_dir();
    authenticate::<false, _>(&base, Kind::X509, false, |result| {
        result.expect("valid X.509 certificate")
    });
}
