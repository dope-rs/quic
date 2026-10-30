use crate::common::peer;
use common::suite::peers::tls;
pub mod common;
use dope_quic::conn::life::options::Options;
use dope_quic::runtime::mux::builder::Builder;
use dope_quic::runtime::mux::builder::Plan;
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::time::{Duration, Instant};

use dope_quic::proto::param;

use common::suite::mux::dispatch::{CID, CLIENT, Capture, SERVER};

#[test]
fn packet_capacity() {
    let mut client = Builder::client(Capture::default())
        .limits(
            Plan::try_new(Plan::standard().connections(), 2, Plan::standard().bytes())
                .expect("packet-capacity test limits are valid"),
        )
        .build()
        .expect("fixed packet limits must form a client router");
    for index in 0..4 {
        Capture::connect(
            &mut client,
            SERVER,
            [7; 32],
            Options::default(),
            vec![index as u8; 8],
            Instant::now(),
        )
        .expect("fixture connect");
    }
    let now = Instant::now();
    Capture::drive(&mut client, now).expect("fixture drive");
    assert_eq!(Pin::new(&mut client).output().capacity(), 2);
    assert_eq!(Pin::new(&mut client).output().len(), 2);
    let mut sent = Pin::new(&mut client).observe(now, |mut turn| turn.output().drain().count());
    while sent < 4 {
        let now = Instant::now();
        Capture::drive(&mut client, now).expect("fixture drive");
        assert!(Pin::new(&mut client).output().len() <= Pin::new(&mut client).output().capacity());
        sent += Pin::new(&mut client).observe(now, |mut turn| turn.output().drain().count());
    }
    assert!(sent >= 4);
    assert!(
        client
            .handler()
            .events
            .borrow()
            .owners
            .iter()
            .all(|(owner, handle)| owner == handle)
    );
}

#[test]
fn byte_budget() {
    let mut tight = Builder::client(Capture::default())
        .limits(
            Plan::try_new(Plan::standard().connections(), 4, 4 * 1200)
                .expect("byte-budget test limits are valid"),
        )
        .build()
        .expect("tight byte limits must form a client router");
    for index in 0..4 {
        Capture::connect(
            &mut tight,
            SERVER,
            [7; 32],
            Options::default(),
            vec![index; 8],
            Instant::now(),
        )
        .expect("fixture connect");
    }
    Capture::drive(&mut tight, Instant::now()).expect("fixture drive");
    assert_eq!(Pin::new(&mut tight).output().len(), 4);
    assert_eq!(Pin::new(&mut tight).output().bytes(), 4 * 1200);

    let mut normal = Builder::client(Capture::default())
        .build()
        .expect("default client router resources must be valid");
    for index in 0..300u16 {
        Capture::connect(
            &mut normal,
            SERVER,
            [7; 32],
            Options::default(),
            index.to_be_bytes().repeat(4),
            Instant::now(),
        )
        .expect("fixture connect");
    }
    while Capture::drive(&mut normal, Instant::now()).expect("fixture drive") != 0 {}
    assert_eq!(Pin::new(&mut normal).output().capacity(), 4096);
    assert_eq!(Pin::new(&mut normal).output().len(), 300);
    assert_eq!(Pin::new(&mut normal).output().bytes(), 300 * 1200);
    for events in [&tight.handler().events, &normal.handler().events] {
        assert!(
            events
                .borrow()
                .owners
                .iter()
                .all(|(owner, handle)| owner == handle)
        );
    }
}

#[test]
fn packet_too_large() {
    let capture = Capture::default();
    let events = Rc::clone(&capture.events);
    let mut client = Builder::client(capture)
        .limits(
            Plan::try_new(Plan::standard().connections(), 4, 1199)
                .expect("sub-packet test limits are valid"),
        )
        .build()
        .expect("sub-packet limits must form a client router");
    let error = Pin::new(&mut client).observe(Instant::now(), |mut turn| {
        turn.protocol().connect(
            SERVER,
            &tls::client([7; 32]).expect("client TLS authority"),
            Options::default(),
            CID.to_vec(),
        )
    });
    assert!(matches!(
        error,
        Err(dope_quic::errors::Connect::InvalidConfig)
    ));
    assert_eq!(Pin::new(&mut client).output().len(), 0);
    assert_eq!(Pin::new(&mut client).output().bytes(), 0);
    assert_eq!(client.active_conns(), 0);
    assert!(events.borrow().closed.is_empty());
    assert!(
        client
            .handler()
            .events
            .borrow()
            .owners
            .iter()
            .all(|(owner, handle)| owner == handle)
    );
}

#[test]
fn server_packet_too_large() {
    use common::suite::mux::install;

    let (key, _) = peer::raw(0x7b).expect("server identity");
    let mut server = Capture::server(
        install::Counter::default(),
        key.server().expect("server TLS"),
        Options::default(),
        Plan::try_new(1, 1, 1199).expect("sub-packet server limits"),
    )
    .expect("server router");
    let error = install::receive(
        &mut server,
        CLIENT,
        &mut install::initial(&CID, &[0x43; 8]).expect("initial packet"),
        Instant::now(),
    );
    assert!(matches!(
        error,
        Err(common::runtime::Error::Receive(
            dope_quic::errors::Receive::Packet(dope_quic::conn::Error::PacketCeiling)
        ))
    ));
    assert_eq!(server.handler().created, 0);
    assert_eq!(server.active_conns(), 0);
    assert_eq!(Pin::new(&mut server).output().len(), 0);
}

#[test]
fn round_robin() {
    let mut client = Builder::client(Capture::default())
        .limits(
            Plan::try_new(Plan::standard().connections(), 2, 1300)
                .expect("round-robin test limits are valid"),
        )
        .build()
        .expect("round-robin limits must form a client router");
    Capture::connect(
        &mut client,
        SERVER,
        [7; 32],
        Options::default(),
        vec![1; 8],
        Instant::now(),
    )
    .expect("fixture connect");
    Capture::connect(
        &mut client,
        SERVER,
        [7; 32],
        Options::default(),
        vec![2; 8],
        Instant::now(),
    )
    .expect("fixture connect");
    let now = Instant::now();
    Capture::drive(&mut client, now).expect("fixture drive");
    assert_eq!(client.active_conns(), 2);
    assert_eq!(Pin::new(&mut client).output().len(), 1);
    assert_eq!(Pin::new(&mut client).output().bytes(), 1200);
    let mut packets =
        Pin::new(&mut client).observe(now, |mut turn| turn.output().drain().collect::<Vec<_>>());
    assert_eq!(packets.len(), 1);
    assert_eq!(Pin::new(&mut client).output().bytes(), 0);
    Capture::drive(&mut client, now).expect("fixture drive");
    assert_eq!(Pin::new(&mut client).output().len(), 1);
    assert_eq!(Pin::new(&mut client).output().bytes(), 1200);
    packets.extend(
        Pin::new(&mut client).observe(now, |mut turn| turn.output().drain().collect::<Vec<_>>()),
    );
    assert_eq!(packets.len(), 2);
    assert!(packets.iter().all(|packet| packet.payload().len() == 1200));
    assert_eq!(Pin::new(&mut client).output().len(), 0);
    assert_eq!(Pin::new(&mut client).output().bytes(), 0);
    assert_eq!(client.active_conns(), 2);
    assert!(
        client
            .handler()
            .events
            .borrow()
            .owners
            .iter()
            .all(|(owner, handle)| owner == handle)
    );
}

#[test]
fn connection_capacity() {
    let mut client = Builder::client(Capture::default())
        .limits(Plan::try_new(1, 8, 16 << 10).expect("single-connection test limits are valid"))
        .build()
        .expect("single-connection limits must form a client router");
    Capture::connect(
        &mut client,
        SERVER,
        [7; 32],
        Options::default(),
        vec![1; 8],
        Instant::now(),
    )
    .expect("fixture connect");
    let second = Pin::new(&mut client).observe(Instant::now(), |mut turn| {
        turn.protocol().connect(
            SERVER,
            &tls::client([7; 32]).expect("client TLS authority"),
            Options::default(),
            vec![2; 8],
        )
    });
    assert!(matches!(second, Err(dope_quic::errors::Connect::Capacity)));
    assert!(
        client
            .handler()
            .events
            .borrow()
            .owners
            .iter()
            .all(|(owner, handle)| owner == handle)
    );
}

#[test]
fn shared_reap_budget() {
    let (signing, key) = peer::raw(9).expect("raw identity");
    let params = param::Set::builder()
        .idle_ms(30_000)
        .initial_data(1 << 20)
        .stream_uni(1 << 20)
        .uni_count(4)
        .try_build()
        .expect("fixture transport parameters");
    let capture = Capture::default();
    let srv_log = Rc::clone(&capture.events);
    let mut server = Capture::server(
        capture,
        signing.server().expect("server TLS"),
        Options::try_from(params.clone())
            .expect("fixture configuration must satisfy its declared bounds"),
        Plan::try_new(Plan::standard().connections(), 10, Plan::standard().bytes())
            .expect("shared-reap test limits are valid"),
    )
    .expect("fixture server");
    let capture = Capture::default();
    let one_log = Rc::clone(&capture.events);
    let mut first = Builder::client(capture)
        .build()
        .expect("first default client router resources must be valid");
    let capture = Capture::default();
    let two_log = Rc::clone(&capture.events);
    let mut second = Builder::client(capture)
        .build()
        .expect("second default client router resources must be valid");
    let one_addr = SocketAddr::from(([10, 0, 0, 1], 50_001));
    let two_addr = SocketAddr::from(([10, 0, 0, 1], 50_002));
    let mut now = Instant::now();
    Capture::connect(
        &mut first,
        SERVER,
        key,
        Options::try_from(params.clone())
            .expect("fixture configuration must satisfy its declared bounds"),
        vec![1; 8],
        now,
    )
    .expect("fixture connect");
    Capture::connect(
        &mut second,
        SERVER,
        key,
        Options::try_from(params).expect("fixture configuration must satisfy its declared bounds"),
        vec![2; 8],
        now,
    )
    .expect("fixture connect");
    for _ in 0..12 {
        for mut outgoing in Capture::output(&mut first, now).expect("fixture output") {
            for segment in outgoing.segments_mut() {
                Capture::recv(&mut server, one_addr, segment, now).expect("fixture recv");
            }
        }
        for mut outgoing in Capture::output(&mut second, now).expect("fixture output") {
            for segment in outgoing.segments_mut() {
                Capture::recv(&mut server, two_addr, segment, now).expect("fixture recv");
            }
        }
        for mut outgoing in Capture::output(&mut server, now).expect("fixture output") {
            let dst = outgoing.addr();
            for segment in outgoing.segments_mut() {
                if dst == one_addr {
                    Capture::recv(&mut first, SERVER, segment, now).expect("fixture recv");
                } else {
                    Capture::recv(&mut second, SERVER, segment, now).expect("fixture recv");
                }
            }
        }
        now += Duration::from_millis(10);
        if srv_log.borrow().established.len() == 2
            && one_log.borrow().established.len() == 1
            && two_log.borrow().established.len() == 1
        {
            break;
        }
    }
    let handles = srv_log.borrow().established.clone();
    assert_eq!(handles.len(), 2);
    for handle in handles {
        Pin::new(&mut server)
            .observe(now, |mut turn| {
                turn.protocol().with_conn(handle, |mut conn| {
                    let mut streams = conn.streams();
                    let mut send = streams.send();
                    let stream = send
                        .open_uni()
                        .expect("established server connection must retain a uni stream slot");
                    send.send(stream, &[7; 128 * 1024])
                        .expect("fixture stream credit must admit the reap payload");
                    send.finish(stream)
                        .expect("fixture send stream must finish once");
                })
            })
            .expect("established server handle must expose its connection");
    }
    now += Duration::from_millis(100);
    let dsts = Capture::output(&mut server, now)
        .expect("fixture output")
        .into_iter()
        .map(|outgoing| outgoing.addr())
        .collect::<Vec<_>>();
    assert!(dsts.len() >= 2);
    assert!(dsts.contains(&one_addr));
    assert!(dsts.contains(&two_addr));
    let prefix = dsts.iter().take_while(|&&addr| addr == dsts[0]).count();
    assert!(prefix < dsts.len());
    assert_eq!(srv_log.borrow().certificates, 0);
    assert_eq!(one_log.borrow().certificates, 0);
    assert_eq!(two_log.borrow().certificates, 0);
    for events in [&srv_log, &one_log, &two_log] {
        assert!(
            events
                .borrow()
                .owners
                .iter()
                .all(|(owner, handle)| owner == handle)
        );
    }
}
