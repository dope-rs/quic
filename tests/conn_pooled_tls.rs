pub mod common;
use common::suite::peers::tls::Capture;
use dope_quic::conn::{self, life};
use dope_quic::errors::{Code, Connect};
use dope_quic::proto::param;
use dope_quic::runtime::mux::builder;
use dope_quic::runtime::routing::Plain;
use dope_quic::wire::{packet::cid, varint::VarInt};
use life::accept;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::{Duration, Instant};

#[test]
fn reserves_max_parameters() {
    let maximum = (param::Set::builder()
        .idle_ms(VarInt::MAX)
        .udp_max(VarInt::MAX)
        .initial_data(VarInt::MAX)
        .local_bidi(VarInt::MAX)
        .remote_bidi(VarInt::MAX)
        .stream_uni(VarInt::MAX)
        .bidi_count(1 << 60)
        .uni_count(1 << 60)
        .ack_exponent(20)
        .ack_ms((1 << 14) - 1)
        .fixed(true)
        .cid_limit(VarInt::MAX)
        .datagram(Some(VarInt::MAX))
        .try_build())
    .expect("maximum transport parameters");
    let cid = (cid::Id::try_from([0; 20])).expect("maximum connection ID");
    let token = [0; 16];
    let mut encoded = Vec::with_capacity(param::Codec::MAX_ENCODED_LEN);
    maximum
        .bind_server(&cid, &cid, Some(&cid), Some(&token))
        .encode(&mut encoded)
        .expect("encode maximum parameters");
    assert_eq!(encoded.len(), param::Codec::MAX_ENCODED_LEN);
    assert_eq!(encoded.capacity(), param::Codec::MAX_ENCODED_LEN);
}

#[test]
fn recycles_direct_leases() {
    let pools = Capture::prepare(
        0x39,
        false,
        Capture::options().expect("fixture transport options"),
    )
    .expect("pooled TLS configuration");
    let (servers, clients, cid) = &pools;
    let cid = *cid;
    assert_eq!(clients.capacity(), 1);
    assert_eq!(servers.capacity(), 1);
    let mut server =
        (servers.accept(accept::Ids::initial(cid, cid, cid))).expect("first server lease");
    let mut client = clients
        .connect::<0>(
            cid,
            cid,
            Capture::options().expect("fixture transport options"),
            Plain,
        )
        .expect("first client lease");
    assert!(matches!(
        clients.connect::<0>(
            cid,
            cid,
            Capture::options().expect("fixture transport options"),
            Plain,
        ),
        Err(Connect::Capacity)
    ));
    assert!(matches!(
        servers.accept(accept::Ids::initial(cid, cid, cid)),
        Err(Connect::Capacity)
    ));
    let now = Instant::now();
    let mut srecv = conn::Workspace::try_new().expect("receive workspace allocation");
    let mut crecv = conn::Workspace::try_new().expect("receive workspace allocation");
    for _ in 0..6 {
        let (packets, send_result) = client.with_scope(|mut scope| scope.output().send(now));
        send_result.expect("client handshake output admission");
        for mut packet in packets {
            assert!(
                server
                    .with_scope(|mut scope| {
                        scope
                            .input(&mut srecv)
                            .recv_packet(&mut packet, now, |_| {})
                    })
                    .is_ok(),
                "client handshake packet"
            );
        }
        let (packets, send_result) = server.with_scope(|mut scope| scope.output().send(now));
        send_result.expect("server handshake output admission");
        for mut packet in packets {
            assert!(
                client
                    .recv_packet(&mut crecv, &mut packet, now, |_: &rustls::Error| {})
                    .is_ok(),
                "server handshake packet"
            );
        }
    }
    assert!(client.view().lifecycle().is_ready());
    assert!(server.view().lifecycle().is_ready());
    let mut client2 = clients
        .connect::<0>(
            cid,
            cid,
            Capture::options().expect("fixture transport options"),
            Plain,
        )
        .expect("client handshake returns its lease");
    let server2 = (servers.accept(accept::Ids::initial(cid, cid, cid)))
        .expect("server handshake returns its lease");
    assert!(client2.view().lifecycle().is_opening());
    assert!(server2.view().lifecycle().is_opening());
    client2.with_scope(|mut scope| scope.lifecycle().close(Code::from_u8(1), Vec::new()));
    assert!(client2.view().lifecycle().is_closing());
    let client3 = clients
        .connect::<0>(
            cid,
            cid,
            Capture::options().expect("fixture transport options"),
            Plain,
        )
        .expect("closing releases admission before close output is sent");
    assert!(client3.view().lifecycle().is_opening());
}

#[test]
fn recycles_mux_leases() {
    let (servers, clients, cid) = Capture::prepare(
        0x4a,
        true,
        Capture::options().expect("fixture transport options"),
    )
    .expect("pooled TLS configuration");
    let limits = (builder::Plan::try_new(4, 64, 1 << 20)).expect("pooled mux limits");
    let server = builder::Builder::server_pool(Capture::default(), &servers);
    let mut server = server
        .limits(limits)
        .build()
        .expect("pooled server mux allocation");
    let mut client = (builder::Builder::client_pool(Capture::default())
        .limits(limits)
        .build())
    .expect("pooled client mux allocation");
    let remote = SocketAddr::from(([10, 0, 0, 2], 443));
    let local = SocketAddr::from(([10, 0, 0, 1], 50_000));
    let started = Instant::now();
    let first = (Pin::new(&mut client).observe(started, |mut turn| {
        turn.protocol().pool_connect(
            remote,
            &clients,
            Capture::options().expect("fixture transport options"),
            vec![0x41; 8],
        )
    }))
    .expect("first pooled client connection");
    assert!(matches!(
        Pin::new(&mut client).observe(started, |mut turn| turn.protocol().pool_connect(
            remote,
            &clients,
            Capture::options().expect("fixture transport options"),
            vec![0x42; 8]
        )),
        Err(Connect::Capacity)
    ));
    let mut delayed = Vec::new();
    for turn in 0..8 {
        let now = started + Duration::from_millis(turn * 10);
        Capture::relay(&mut client, &mut server, local, now).expect("pooled TLS relay");
        let packets = Capture::take(&mut server, now).expect("pooled TLS take");
        let (mut app, mut hs): (Vec<_>, Vec<_>) = packets.into_iter().partition(|packet| {
            packet
                .payload()
                .first()
                .is_some_and(|byte| byte & 0x80 == 0)
        });
        delayed.append(&mut app);
        Capture::deliver(&mut client, remote, &mut hs, now).expect("pooled TLS deliver");
    }
    let server1 = (server.handler().last_created).expect("server accepted the first connection");
    assert!(
        client
            .conn(first)
            .is_some_and(|conn| conn.view().lifecycle().is_ready())
    );
    assert!(
        server
            .conn(server1)
            .is_some_and(|conn| conn.view().lifecycle().is_ready())
    );
    assert!(!delayed.is_empty());
    let at2 = started + Duration::from_millis(100);
    let second = (Pin::new(&mut client).observe(at2, |mut turn| {
        turn.protocol().pool_connect(
            remote,
            &clients,
            Capture::options().expect("fixture transport options"),
            vec![0x43; 8],
        )
    }))
    .expect("second pooled client connection");
    assert!(matches!(
        Pin::new(&mut client).observe(at2, |mut turn| turn.protocol().pool_connect(
            remote,
            &clients,
            Capture::options().expect("fixture transport options"),
            vec![0x44; 8]
        )),
        Err(Connect::Capacity)
    ));
    Capture::relay(&mut client, &mut server, local, at2).expect("pooled TLS relay");
    assert!(matches!(
        servers.accept(accept::Ids::initial(cid, cid, cid)),
        Err(Connect::Capacity)
    ));
    let at = started + Duration::from_millis(101);
    Capture::deliver(&mut client, remote, &mut delayed, at).expect("pooled TLS deliver");
    assert!(matches!(
        clients.connect::<0>(
            cid,
            cid,
            Capture::options().expect("fixture transport options"),
            Plain,
        ),
        Err(Connect::Capacity)
    ));
    for turn in 0..8 {
        let now = started + Duration::from_millis(110 + turn * 10);
        Capture::relay(&mut server, &mut client, remote, now).expect("pooled TLS relay");
        Capture::relay(&mut client, &mut server, local, now).expect("pooled TLS relay");
    }
    assert!(client.conn(first).is_some());
    assert!(
        client
            .conn(second)
            .is_some_and(|conn| conn.view().lifecycle().is_ready())
    );
    assert_eq!(client.handler().established, 2);
    assert_eq!(server.handler().established, 2);
    let at3 = started + Duration::from_millis(200);
    let third = (Pin::new(&mut client).observe(at3, |mut turn| {
        turn.protocol().pool_connect(
            remote,
            &clients,
            Capture::options().expect("fixture transport options"),
            vec![0x45; 8],
        )
    }))
    .expect("third pooled client connection");
    let server3 =
        (servers.accept(accept::Ids::initial(cid, cid, cid))).expect("third server lease");
    assert!(
        client
            .conn(third)
            .is_some_and(|conn| conn.view().lifecycle().is_opening())
    );
    assert!(server3.view().lifecycle().is_opening());
    Pin::new(&mut client)
        .observe(at3, |mut turn| {
            turn.protocol().with_conn(third, |mut scope| {
                scope.lifecycle().close(Code::from_u8(1), Vec::new());
            })
        })
        .expect("close the opening client without transmitting close output");
    let fourth = clients
        .connect::<0>(
            cid,
            cid,
            Capture::options().expect("fixture transport options"),
            Plain,
        )
        .expect("mux closing releases its opening admission");
    assert!(fourth.view().lifecycle().is_opening());
}
