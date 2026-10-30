pub mod common;
use crate::common::peer;
use std::time::{Duration, Instant};

use dope_quic::conn::{output::transmit, stream::SendOutcome, wire::packet::Batch};
use dope_quic::errors::Code;
use dope_quic::stream::send;
use o3::buffer::storage;
use peer::Bind as _;
use peer::Config;
use peer::Event;
use peer::Pair;
use peer::Receiver as _;
use peer::Scope as _;
use peer::flight::Flight;

#[test]
fn owners_wait_for_prefix() {
    let mut config = Config::new(1 << 20, 1 << 20, 0, 1);
    config.local = Some([0, 1]);
    let (mut server, mut client, mut work) = match Pair::try_new(
        config
            .try_build()
            .expect("fixture configuration must satisfy its declared bounds"),
        config
            .try_build()
            .expect("fixture configuration must satisfy its declared bounds"),
    ) {
        Ok(Pair {
            server,
            client,
            work,
        }) => Some((server, client, work)),
        _ => None,
    }
    .expect("connection pair must initialize");
    let stream = client
        .send_streams()
        .open_uni()
        .expect("client can open retained stream");
    let sent_at = Instant::now() + Duration::from_secs(1);

    let (first, second) = match [0x71, 0x72]
        .map(|byte| storage::Shared::try_from(&mut vec![byte; 700]).map(send::Buffer::Retained))
    {
        [Ok(first), Ok(second)] => Some((first, second)),
        _ => None,
    }
    .expect("retained test buffers must preserve their owners");
    let parts = send::Parts::new(first, Some(second), send::Boundary::End);
    assert!(
        matches!(
            client.send_streams().try_parts(stream, parts),
            SendOutcome::Accepted
        ),
        "both retained owners must fit the configured send limits"
    );
    let mut flight = Batch::default();
    client
        .with_scope(|mut scope| scope.output().send_batch(&mut flight, sent_at, 2, 1_200))
        .expect("configured client journals must admit the scheduled flight");
    assert_eq!(flight.packets(), 2);
    let mut packets = flight.iter().map(<[u8]>::to_vec).collect::<Vec<_>>();
    let mut original = [packets.remove(0)];
    let mut suffix = packets;
    for packet in suffix.iter_mut() {
        server
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(packet, sent_at, |_: &rustls::Error| {})
            })
            .expect("server accepts suffix packet");
    }

    let ack_at = server
        .view()
        .recovery()
        .send_at(sent_at + Duration::from_millis(1));
    let (packets, result) = server.with_scope(|mut scope| scope.output().send(ack_at));
    result.expect("configured server journals must admit the scheduled ACK");
    for mut packet in packets {
        client
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(&mut packet, ack_at, |_: &rustls::Error| {})
            })
            .expect("client accepts suffix acknowledgement");
    }
    let prefix = ack_at;
    for packet in original.iter_mut() {
        server
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(packet, prefix, |_: &rustls::Error| {})
            })
            .expect("server accepts delayed prefix packet");
    }
    let mut expected = vec![0x71; 700];
    expected.resize(1_400, 0x72);
    let peer = stream.bind(&server);
    let peer = (peer).expect("paired stream must resolve");
    assert_eq!(
        server
            .recv()
            .recv_owned(peer)
            .expect("server assembles retained stream prefix")
            .as_deref(),
        Some(expected.as_slice())
    );

    let ack2_at = server.view().recovery().send_at(prefix);
    let (ack2, result) = server.with_scope(|mut scope| scope.output().send(ack2_at));
    result.expect("configured server journals must admit the second ACK");
    assert!(!ack2.is_empty());
    for mut packet in ack2 {
        client
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(&mut packet, ack2_at, |_: &rustls::Error| {})
            })
            .expect("client accepts prefix acknowledgement");
    }
    assert!(client.view().lifecycle().is_ready());
    assert!(client.view().lifecycle().is_ready() && server.view().lifecycle().is_ready());
}

#[test]
fn late_control_keeps_slot() {
    let mut config = Config::new(64, 1 << 20, 0, 2);
    config.local = Some([0, 2]);
    let local = config
        .try_build()
        .expect("fixture configuration must satisfy its declared bounds");
    let delay = Duration::from_millis(u64::from(local.params().timing().ack_ms()));
    let (mut server, mut client, mut work) = match Pair::try_new(
        local,
        config
            .try_build()
            .expect("fixture configuration must satisfy its declared bounds"),
    ) {
        Ok(Pair {
            server,
            client,
            work,
        }) => Some((server, client, work)),
        _ => None,
    }
    .expect("connection pair must initialize");
    let victim = client
        .send_streams()
        .open_uni()
        .expect("client can open victim stream");
    let anchor = client
        .send_streams()
        .open_uni()
        .expect("client can open anchor stream");
    let old_recv = victim.bind(&server);
    let held_rx = anchor.bind(&server);
    let (old_recv, held_rx) = match (old_recv, held_rx) {
        (Ok(old_recv), Ok(held_rx)) => Some((old_recv, held_rx)),
        _ => None,
    }
    .expect("paired streams must resolve");
    client
        .send_streams()
        .send(victim, &[0x51; 64])
        .expect("queue victim bytes");
    client
        .send_streams()
        .send(anchor, &[0x52; 64])
        .expect("queue anchor bytes");

    let sent_at = Instant::now() + Duration::from_secs(1);
    let mut initial = Batch::default();
    client
        .with_scope(|mut scope| scope.output().send_batch(&mut initial, sent_at, 4, 1_200))
        .expect("configured client journals must admit the initial schedule");
    assert!(!initial.is_empty());
    for packet in initial.iter_mut() {
        server
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(packet, sent_at, |_: &rustls::Error| {})
            })
            .expect("server accepts initial stream packet");
    }

    let mut received = Vec::with_capacity(128);
    assert_eq!(server.recv().recv(old_recv, &mut received), Ok(64));
    assert_eq!(received, [0x51; 64]);

    let ctrl_at = server
        .view()
        .recovery()
        .send_at(sent_at + Duration::from_millis(1));
    let mut old_ctrl = Batch::default();
    server
        .with_scope(|mut scope| scope.output().send_batch(&mut old_ctrl, ctrl_at, 1, 1_200))
        .expect("configured server journals must admit the old control packet");
    assert!(!old_ctrl.is_empty());
    for packet in old_ctrl.iter_mut() {
        client
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(packet, ctrl_at, |_: &rustls::Error| {})
            })
            .expect("client accepts original control packet");
    }

    let old_at = client.view().recovery().send_at(ctrl_at + delay);
    let mut late_ack = Batch::default();
    let late_ack = Flight::emit_at(&mut client, &mut late_ack, old_at, 1, 1_200)
        .expect("pre-admitted late ACK journals must accept the flight");
    assert!(!late_ack.is_empty());
    assert!(late_ack.effects().contains(transmit::Effects::ACK));

    client
        .send_streams()
        .reset(victim, Code::from_u8(0x61))
        .expect("reset victim stream");
    let reset_at = old_at + Duration::from_millis(1);
    let mut reset = Batch::default();
    client
        .with_scope(|mut scope| scope.output().send_batch(&mut reset, reset_at, 1, 1_200))
        .expect("configured client journals must admit the reset packet");
    assert!(!reset.is_empty());

    server
        .recv()
        .stop(old_recv, Code::from_u8(0x62))
        .expect("stop victim receive stream");
    let loss_at = server
        .view()
        .recovery()
        .next_timer()
        .expect("control PTO is armed")
        + Duration::from_millis(1);
    assert_eq!(
        server.with_scope(|mut scope| scope.recovery().try_loss(loss_at)),
        Ok(())
    );
    for packet in reset.iter_mut() {
        server
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(packet, loss_at, |_: &rustls::Error| {})
            })
            .expect("server accepts reset packet");
    }

    let free_at = server
        .view()
        .recovery()
        .send_at(loss_at + Duration::from_millis(1));
    let mut packets = Batch::default();
    server
        .with_scope(|mut scope| scope.output().send_batch(&mut packets, free_at, 2, 1_200))
        .expect("configured server journals must admit the free-window packets");
    assert!(!packets.is_empty());
    for packet in packets.iter_mut() {
        client
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(packet, free_at, |_: &rustls::Error| {})
            })
            .expect("client accepts reset acknowledgement and probe");
    }
    assert!(server.poll().poll_event() == Some(Event::Readable { stream_id: held_rx }));
    assert!(
        server.poll().poll_event()
            == Some(Event::Reset {
                stream_id: old_recv,
                error_code: dope_quic::errors::Code::from_u8(0x61),
            })
    );
    let limit_at = server
        .view()
        .recovery()
        .send_at(free_at + Duration::from_millis(1));
    server
        .with_scope(|mut scope| scope.output().send_batch(&mut packets, limit_at, 2, 1_200))
        .expect("configured server journals must admit the limited-window packets");
    for packet in packets.iter_mut() {
        client
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(packet, limit_at, |_: &rustls::Error| {})
            })
            .expect("client accepts replenished stream limit");
    }

    let next = client
        .send_streams()
        .open_uni()
        .expect("the reset victim frees its send and receive slots");
    let new_recv = next.bind(&server);
    let new_recv = (new_recv).expect("replacement stream must resolve");
    client
        .send_streams()
        .send(next, &[0x53; 64])
        .expect("queue replacement bytes");
    let mut first = Batch::default();
    let flight = Flight::emit_due(
        &mut client,
        &mut first,
        limit_at + Duration::from_millis(1),
        1,
        1_200,
    )
    .expect("replacement flight admitted");
    let new_at = flight.sent_at();
    assert!(
        flight.effects().contains(transmit::Effects::FRESH_STREAM),
        "replacement flight did not commit a fresh STREAM range",
    );
    flight
        .deliver(&mut work, &mut server)
        .expect("replacement flight must reach its peer");

    received.clear();
    assert_eq!(server.recv().recv(new_recv, &mut received), Ok(64));
    assert_eq!(received, [0x53; 64]);

    let late_at = new_at + Duration::from_millis(1);
    late_ack
        .deliver_at(&mut work, &mut server, late_at)
        .expect("delayed acknowledgment must reach its peer after emission");

    let grant_at = server
        .view()
        .recovery()
        .send_at(late_at + Duration::from_millis(1));
    let mut credit = Batch::default();
    server
        .with_scope(|mut scope| scope.output().send_batch(&mut credit, grant_at, 1, 1_200))
        .expect("configured server journals must admit the credit grant");
    assert!(!credit.is_empty());
    for packet in credit.iter_mut() {
        client
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(packet, grant_at, |_: &rustls::Error| {})
            })
            .expect("client accepts replacement credit");
    }

    client
        .send_streams()
        .send(next, &[0x53; 64])
        .expect("queue second replacement segment");
    client
        .send_streams()
        .finish(next)
        .expect("finish replacement stream");
    client
        .send_streams()
        .finish(anchor)
        .expect("finish anchor stream");
    for turn in 1..=16 {
        let now = grant_at + Duration::from_millis(turn * 10);
        let received = server.receive_from(&mut work, &mut client, now);
        assert!(received.is_ok());
        let received = client.receive_from(&mut work, &mut server, now);
        assert!(received.is_ok());
    }

    assert_eq!(server.recv().recv(new_recv, &mut received), Ok(64));
    assert_eq!(received, [0x53; 128]);
    let mut held_buf = Vec::new();
    assert_eq!(server.recv().recv(held_rx, &mut held_buf), Ok(64));
    assert_eq!(held_buf, [0x52; 64]);
    assert!(
        server
            .stream_state()
            .recv_eof(new_recv)
            .expect("replacement receive stream remains addressable")
    );
    assert!(
        server
            .stream_state()
            .recv_eof(held_rx)
            .expect("anchor receive stream remains addressable")
    );
    assert!(client.view().lifecycle().is_ready() && server.view().lifecycle().is_ready());
}
