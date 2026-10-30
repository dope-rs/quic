use common::peer::Config;
use common::peer::Pair;
use common::peer::Receiver;
use common::peer::Scope as _;
pub mod common;
use common::peer;
use peer::Bind;

use dope_quic::conn::life::options::Options;
use dope_quic::errors::Code;
use peer::Event;

use std::time::{Duration, Instant};

use dope_quic::conn::{stream::SendOutcome, wire::packet::Batch};
use dope_quic::stream::send;
use o3::buffer::storage;

#[test]
fn higher_ids_open_peers() {
    let (mut server, mut client, mut work) =
        Pair::try_default().expect("connected peers").into_parts();

    let low_bidi = client
        .send_streams()
        .open_bidi()
        .expect("client can open lower bidirectional stream");
    let hi_bidi = client
        .send_streams()
        .open_bidi()
        .expect("client can open higher bidirectional stream");
    let low_peer = Bind::bind(low_bidi, &server).expect("peer stream");
    let hi_peer = Bind::bind(hi_bidi, &server).expect("peer stream");
    assert_eq!((low_bidi.get(), hi_bidi.get()), (0, 4));
    client
        .send_streams()
        .send(hi_bidi, b"higher client bidi")
        .expect("queue higher client stream bytes");
    client
        .send_streams()
        .finish(hi_bidi)
        .expect("finish higher client stream");

    let sent_at = Instant::now() + Duration::from_secs(1);
    Receiver::receive_from(&mut server, &mut work, &mut client, sent_at)
        .expect("peer packet transfer");
    assert_eq!(
        server
            .recv()
            .recv_owned(hi_peer)
            .expect("server receives higher client stream")
            .as_deref(),
        Some(&b"higher client bidi"[..])
    );
    server
        .send_streams()
        .send(low_peer, b"implicit bidi response")
        .expect("queue response on implicitly opened lower stream");
    server
        .send_streams()
        .finish(low_peer)
        .expect("finish lower response stream");

    let reply_at = sent_at + Duration::from_secs(1);
    Receiver::receive_from(&mut client, &mut work, &mut server, reply_at)
        .expect("peer packet transfer");
    assert_eq!(
        client
            .recv()
            .recv_owned(low_bidi)
            .expect("client receives lower response stream")
            .as_deref(),
        Some(&b"implicit bidi response"[..])
    );

    let low_uni = server
        .send_streams()
        .open_uni()
        .expect("server can open lower unidirectional stream");
    let hi_uni = server
        .send_streams()
        .open_uni()
        .expect("server can open higher unidirectional stream");
    assert_eq!((low_uni.get(), hi_uni.get()), (3, 7));
    server
        .send_streams()
        .send(hi_uni, b"higher server uni")
        .expect("queue higher server stream bytes");
    server
        .send_streams()
        .finish(hi_uni)
        .expect("finish higher server stream");

    let uni_at = reply_at + Duration::from_secs(1);
    Receiver::receive_from(&mut client, &mut work, &mut server, uni_at)
        .expect("peer packet transfer");
    let hi_recv = Bind::bind(hi_uni, &client).expect("peer stream");
    let low_recv = Bind::bind(low_uni, &client).expect("peer stream");
    assert_eq!(
        client
            .recv()
            .recv_owned(hi_recv)
            .expect("client receives higher server stream")
            .as_deref(),
        Some(&b"higher server uni"[..])
    );
    client
        .recv()
        .stop(low_recv, Code::from_u8(0x52))
        .expect("stop implicitly opened lower stream");

    let stop_at = uni_at + Duration::from_secs(1);
    Receiver::receive_from(&mut server, &mut work, &mut client, stop_at)
        .expect("peer packet transfer");
    assert!(
        server.poll().poll_event()
            == Some(Event::Stopped {
                stream_id: low_uni,
                error_code: dope_quic::errors::Code::from_u8(0x52),
            })
    );
    assert!(client.view().lifecycle().is_ready() && server.view().lifecycle().is_ready());
}

#[test]
fn drained_reschedules() {
    let (mut server, mut client, mut work) =
        Pair::try_default().expect("connected peers").into_parts();
    let stream = client
        .send_streams()
        .open_bidi()
        .expect("client can open rescheduled stream");
    let peer = Bind::bind(stream, &server).expect("peer stream");
    let now = Instant::now();

    client
        .send_streams()
        .send(stream, b"first")
        .expect("queue first scheduled bytes");
    Receiver::receive_from(&mut server, &mut work, &mut client, now).expect("peer packet transfer");
    client
        .send_streams()
        .send(stream, b"second")
        .expect("reschedule drained stream");
    Receiver::receive_from(&mut server, &mut work, &mut client, now).expect("peer packet transfer");

    assert_eq!(
        server
            .recv()
            .recv_owned(peer)
            .expect("server receives both scheduled writes")
            .as_deref(),
        Some(&b"firstsecond"[..])
    );
}

#[test]
fn late_ack_keeps_slot() {
    fn config() -> Options {
        (Config::new(1 << 20, 1 << 20, 0, 4)
            .try_build()
            .expect("fixture transport parameters")
            .into_builder()
            .streams(|streams| streams.local_bidi(0).local_uni(2))
            .try_build())
        .expect("fixture connection options")
    }

    let ack_wait = Duration::from_millis(u64::from(config().params().timing().ack_ms()));
    let (mut server, mut client, mut work) = Pair::try_new(config(), config())
        .expect("connected peers")
        .into_parts();
    let victim = client
        .send_streams()
        .open_uni()
        .expect("client can open victim stream");
    let anchor = client
        .send_streams()
        .open_uni()
        .expect("client can open anchor stream");
    let old_data = [0x41; 64];
    let keep_buf = [0x42; 4_096];
    let new_data = [0x43; 128];
    let owner = (storage::Shared::try_from(&mut old_data.to_vec()))
        .expect("victim buffer must preserve its owner");
    assert!(matches!(
        client
            .send_streams()
            .try_buffer(victim, send::Buffer::Retained(owner)),
        SendOutcome::Accepted
    ));
    client
        .send_streams()
        .finish(victim)
        .expect("finish victim stream");
    client
        .send_streams()
        .send(anchor, &keep_buf)
        .expect("queue anchor stream bytes");

    let sent_at = Instant::now() + Duration::from_secs(1);
    let mut original = Batch::default();
    client
        .with_scope(|mut scope| scope.output().send_batch(&mut original, sent_at, 1, 1_200))
        .expect("warmed client journals must admit the original stream packet");
    assert_eq!(original.packets(), 1);
    for packet in original.iter_mut() {
        server
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(packet, sent_at, |_: &rustls::Error| {})
            })
            .expect("server accepts original packet");
    }
    let ack_at = server.view().recovery().send_at(sent_at + ack_wait);
    let mut first = Batch::default();
    server
        .with_scope(|mut scope| scope.output().send_batch(&mut first, ack_at, 1, 1_200))
        .expect("warmed server journals must admit the first stream acknowledgement");
    assert!(!first.is_empty());

    let deadline = client
        .view()
        .recovery()
        .next_timer()
        .expect("stream PTO is armed");
    let probe_at = deadline + Duration::from_millis(1);
    assert_eq!(
        client.with_scope(|mut scope| scope.recovery().try_loss(probe_at)),
        Ok(())
    );
    let mut probe = Batch::default();
    client
        .with_scope(|mut scope| scope.output().send_batch(&mut probe, probe_at, 1, 1_200))
        .expect("warmed client journals must admit the stream probe");
    assert_eq!(probe.packets(), 1);
    for packet in probe.iter_mut() {
        server
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(packet, probe_at, |_: &rustls::Error| {})
            })
            .expect("server accepts probe packet");
    }
    let late_at = server
        .view()
        .recovery()
        .send_at(probe_at + Duration::from_millis(30));
    let mut late_ack = Batch::default();
    server
        .with_scope(|mut scope| scope.output().send_batch(&mut late_ack, late_at, 1, 1_200))
        .expect("warmed server journals must admit the late stream acknowledgement");
    assert!(!late_ack.is_empty());
    let retire = late_at + Duration::from_millis(1);
    for packet in first.iter_mut() {
        client
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(packet, retire, |_: &rustls::Error| {})
            })
            .expect("client accepts first acknowledgement");
    }
    let next = client
        .send_streams()
        .open_uni()
        .expect("the acknowledged FIN retires and frees the victim slot");
    client
        .send_streams()
        .send(next, &new_data)
        .expect("queue replacement stream bytes");
    client
        .send_streams()
        .finish(next)
        .expect("finish replacement stream");

    for packet in late_ack.iter_mut() {
        client
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(packet, retire, |_: &rustls::Error| {})
            })
            .expect("client accepts delayed acknowledgement");
    }
    client
        .send_streams()
        .finish(anchor)
        .expect("finish anchor stream");

    for turn in 1..=16 {
        let now = retire + Duration::from_millis(turn * 10);
        Receiver::receive_from(&mut server, &mut work, &mut client, now)
            .expect("peer packet transfer");
        Receiver::receive_from(&mut client, &mut work, &mut server, now)
            .expect("peer packet transfer");
    }

    let old_recv = Bind::bind(victim, &server).expect("peer stream");
    let held_rx = Bind::bind(anchor, &server).expect("peer stream");
    let new_recv = Bind::bind(next, &server).expect("peer stream");

    assert_eq!(
        server
            .recv()
            .recv_owned(old_recv)
            .expect("server receives victim stream")
            .as_deref(),
        Some(old_data.as_slice())
    );
    assert_eq!(
        server
            .recv()
            .recv_owned(held_rx)
            .expect("server receives anchor stream")
            .as_deref(),
        Some(keep_buf.as_slice())
    );
    assert_eq!(
        server
            .recv()
            .recv_owned(new_recv)
            .expect("server receives replacement stream")
            .as_deref(),
        Some(new_data.as_slice())
    );
    assert!(client.view().lifecycle().is_ready() && server.view().lifecycle().is_ready());
}
