pub mod common;
use crate::common::peer;
use std::time::{Duration, Instant};

use dope_quic::conn::stream::{Error, SendOutcome};
use dope_quic::errors::Code;
use dope_quic::stream::send;
use o3::buffer::storage;
use peer::Config;
use peer::Pair;
use peer::Receiver as _;
use peer::Scope as _;

/// A smaller borrowed send consumes the warmed owner as one accounting
/// transition; its 64-byte capacity proves the cache path was reused.
/// Cache is evictable and therefore cannot block application-owned output.
#[test]
fn copied_cache_lifecycle() {
    let options = (Config::default()
        .try_build()
        .expect("fixture configuration must satisfy its declared bounds")
        .into_builder()
        .streams(|streams| streams.resident(64))
        .try_build())
    .expect("fixture configuration must satisfy its declared bounds");
    let Pair {
        mut server,
        mut client,
        mut work,
    } = Pair::try_new(
        Config::default()
            .try_build()
            .expect("fixture configuration must satisfy its declared bounds"),
        options,
    )
    .expect("connection pair initializes");
    let stream = client
        .send_streams()
        .open_bidi()
        .expect("default options grant a bidirectional stream");
    let copied = [0x61; 64];

    client
        .send_streams()
        .send(stream, &copied)
        .expect("64 bytes fit the resident ceiling");
    assert_eq!(client.stream_state().active_bytes(), 64);
    assert_eq!(client.stream_state().cached_bytes(), 0);
    assert_eq!(client.stream_state().resident(), 64);

    let sent = Instant::now() + Duration::from_secs(1);
    let received = server.receive_from(&mut work, &mut client, sent);
    assert!(received.is_ok());
    let ack = server
        .view()
        .recovery()
        .send_at(sent + Duration::from_millis(30));
    let received = client.receive_from(&mut work, &mut server, ack);
    assert!(received.is_ok());

    assert_eq!(client.stream_state().active_bytes(), 0);
    assert_eq!(client.stream_state().cached_bytes(), 64);
    assert_eq!(client.stream_state().resident(), 64);

    client
        .send_streams()
        .send(stream, &[0x63; 32])
        .expect("warmed owner covers the smaller send");
    assert_eq!(client.stream_state().wire_bytes(), 32);
    assert_eq!(client.stream_state().active_bytes(), 64);
    assert_eq!(client.stream_state().cached_bytes(), 0);
    let sent = ack + Duration::from_secs(1);
    let received = server.receive_from(&mut work, &mut client, sent);
    assert!(received.is_ok());
    let ack = server
        .view()
        .recovery()
        .send_at(sent + Duration::from_millis(30));
    let received = client.receive_from(&mut work, &mut server, ack);
    assert!(received.is_ok());
    assert_eq!(client.stream_state().cached_bytes(), 64);

    assert!(
        matches!(
            client
                .send_streams()
                .try_buffer(stream, send::Buffer::Owned(vec![0x62; 64])),
            SendOutcome::Accepted
        ),
        "cached owner must be evictable for the 64-byte owned send"
    );
    assert_eq!(client.stream_state().active_bytes(), 64);
    assert_eq!(client.stream_state().cached_bytes(), 0);
    assert_eq!(client.stream_state().resident(), 64);

    let sent = ack + Duration::from_secs(1);
    let received = server.receive_from(&mut work, &mut client, sent);
    assert!(received.is_ok());
    let ack = server
        .view()
        .recovery()
        .send_at(sent + Duration::from_millis(30));
    let received = client.receive_from(&mut work, &mut server, ack);
    assert!(received.is_ok());

    assert_eq!(client.stream_state().wire_bytes(), 0);
    assert_eq!(client.stream_state().resident(), 0);
    assert_eq!(client.stream_state().cached_bytes(), 0);
}

/// Inline storage fills the wire budget while retaining the warmed cache.
#[test]
fn borrowed_cache_block() {
    let options = (Config::default()
        .try_build()
        .expect("fixture configuration must satisfy its declared bounds")
        .into_builder()
        .streams(|streams| streams.send_bytes(64).resident(64))
        .try_build())
    .expect("fixture configuration must satisfy its declared bounds");
    let Pair {
        mut server,
        mut client,
        mut work,
    } = Pair::try_new(
        Config::default()
            .try_build()
            .expect("fixture configuration must satisfy its declared bounds"),
        options,
    )
    .expect("connection pair initializes");
    let stream = client
        .send_streams()
        .open_bidi()
        .expect("default options grant a bidirectional stream");

    client
        .send_streams()
        .send(stream, &[0x71; 64])
        .expect("64 bytes fit both send ceilings");
    let sent = Instant::now() + Duration::from_secs(1);
    let received = server.receive_from(&mut work, &mut client, sent);
    assert!(received.is_ok());
    let ack = server
        .view()
        .recovery()
        .send_at(sent + Duration::from_millis(30));
    let received = client.receive_from(&mut work, &mut server, ack);
    assert!(received.is_ok());
    assert_eq!(client.stream_state().cached_bytes(), 64);

    for bytes in [&[0x72; 16][..]; 4] {
        assert!(matches!(
            client.send_streams().try_buffer(
                stream,
                send::Buffer::inline(bytes).expect("inline fixture payload fits"),
            ),
            SendOutcome::Accepted,
        ));
    }
    assert_eq!(client.stream_state().wire_bytes(), 64);
    assert_eq!(client.stream_state().resident(), 64);

    assert_eq!(
        client.send_streams().send(stream, &[0x73; 64]),
        Err(Error::Capacity)
    );
    assert_eq!(client.stream_state().wire_bytes(), 64);
    assert_eq!(client.stream_state().cached_bytes(), 64);
    assert_eq!(client.stream_state().resident(), 64);
}

#[test]
fn reset_external_owners() {
    let options = (Config::default()
        .try_build()
        .expect("fixture configuration must satisfy its declared bounds")
        .into_builder()
        .streams(|streams| streams.resident(128).send_parts(2))
        .try_build())
    .expect("fixture configuration must satisfy its declared bounds");
    let mut pair = Pair::try_new(
        Config::default()
            .try_build()
            .expect("fixture configuration must satisfy its declared bounds"),
        options,
    )
    .expect("test precondition");
    let client = &mut pair.client;
    let stream = client
        .send_streams()
        .open_bidi()
        .expect("default options grant a bidirectional stream");
    let retained = (storage::Shared::try_from(&mut vec![0x82; 64]))
        .expect("nonempty vector must preserve its owner");

    let parts = send::Parts::new(
        send::Buffer::Owned(vec![0x81; 64]),
        Some(send::Buffer::Retained(retained)),
        send::Boundary::More,
    );
    assert!(
        matches!(
            client.send_streams().try_parts(stream, parts),
            SendOutcome::Accepted
        ),
        "two 64-byte parts must fit the resident and segment ceilings"
    );
    assert_eq!(client.stream_state().active_bytes(), 128);
    assert_eq!(client.stream_state().cached_bytes(), 0);
    assert_eq!(client.stream_state().segments(), 2);

    client
        .send_streams()
        .reset(stream, Code::from_u8(0x83))
        .expect("open stream can be reset");

    assert_eq!(client.stream_state().wire_bytes(), 0);
    assert_eq!(client.stream_state().resident(), 0);
    assert_eq!(client.stream_state().active_bytes(), 0);
    assert_eq!(
        client.stream_state().cached_bytes(),
        0,
        "reset may recycle only a connection-minted CopiedOwner",
    );
    assert_eq!(client.stream_state().segments(), 0);
}
