pub mod common;

use dope_quic::conn;
use dope_quic::conn::life::options::Options;
use dope_quic::conn::life::options::builder;
use dope_quic::proto::param;
use dope_quic::wire::packet::cid;

#[test]
fn param_bounds() {
    assert!(matches!(
        param::Set::builder().udp_max(1_199).try_build(),
        Err(param::Error::OutOfRange {
            id: 0x03,
            value: 1_199,
            minimum: 1_200,
            ..
        })
    ));
    for value in [21, u64::MAX] {
        assert!(
            param::Set::builder().ack_exponent(value).try_build()
                == Err(param::Error::OutOfRange {
                    id: 0x0a,
                    value,
                    minimum: 0,
                    maximum: 20,
                })
        );
    }
    assert!(matches!(
        param::Set::builder().cid_limit(1).try_build(),
        Err(param::Error::OutOfRange {
            id: 0x0e,
            value: 1,
            minimum: 2,
            ..
        })
    ));
}

#[test]
fn option_promotion() {
    assert!(matches!(
        Options::builder()
            .streams(|streams| streams.recv_parts(0))
            .try_build(),
        Err(builder::Invalid::ReceiveSegments {
            actual: 0,
            minimum: 1,
            maximum: 65_536,
        })
    ));
    assert!(matches!(
        Options::builder()
            .streams(|streams| streams.send_bytes(0))
            .try_build(),
        Err(builder::Invalid::SendBytes {
            actual: 0,
            minimum: 1,
            maximum,
        }) if maximum == usize::MAX
    ));
    assert!(matches!(
        Options::builder()
            .transport(|transport| transport.max_pmtu(1_199))
            .try_build(),
        Err(builder::Invalid::Pmtu {
            actual: 1_199,
            minimum: 1_200,
            maximum: 65_527,
        })
    ));
}

#[test]
fn datagram_capacity_proof() {
    assert!(matches!(
        Options::builder()
            .datagrams(|dgram| dgram.pending(65_537))
            .try_build(),
        Err(builder::Invalid::PendingDatagrams {
            actual: 65_537,
            minimum: 0,
            maximum: 65_536,
        })
    ));
    assert!(matches!(
        Options::builder()
            .datagrams(|dgram| dgram.incoming(65_537))
            .try_build(),
        Err(builder::Invalid::IncomingDatagrams {
            actual: 65_537,
            minimum: 0,
            maximum: 65_536,
        })
    ));
}

#[test]
fn stream_limit_proof() {
    assert!(matches!(
        Options::builder()
            .streams(|streams| streams.recv_parts(65_537))
            .try_build(),
        Err(builder::Invalid::ReceiveSegments {
            actual: 65_537,
            minimum: 1,
            maximum: 65_536,
        })
    ));
    assert!(matches!(
        Options::builder()
            .streams(|streams| streams.resident(0))
            .try_build(),
        Err(builder::Invalid::SendResident {
            actual: 0,
            minimum: 1,
            maximum,
        }) if maximum == usize::MAX
    ));
    assert!(matches!(
        Options::builder()
            .streams(|streams| streams.send_parts(65_537))
            .try_build(),
        Err(builder::Invalid::SendSegments {
            actual: 65_537,
            minimum: 1,
            maximum: 65_536,
        })
    ));
}

#[test]
fn path_limit_proof() {
    let params = (param::Set::builder()
        .initial_data((1 << 30) + 1)
        .try_build())
    .expect("fixture transport parameters");
    assert!(matches!(
        Options::builder()
            .transport(|transport| transport.params(params))
            .try_build(),
        Err(builder::Invalid::InitialData {
            actual: 1_073_741_825,
            minimum: 0,
            maximum: 1_073_741_824,
        })
    ));
    let params =
        (param::Set::builder().cid_limit(9).try_build()).expect("fixture transport parameters");
    assert!(matches!(
        Options::builder()
            .transport(|transport| transport.params(params))
            .try_build(),
        Err(builder::Invalid::ConnectionIds {
            actual: 9,
            minimum: 2,
            maximum: 8,
        })
    ));
}

#[test]
fn stream_count_proof() {
    let params = (param::Set::builder().bidi_count(65_537).try_build())
        .expect("fixture transport parameters");
    assert!(matches!(
        Options::builder()
            .transport(|transport| transport.params(params))
            .try_build(),
        Err(builder::Invalid::PeerBidi {
            actual: 65_537,
            minimum: 0,
            maximum: 65_536,
        })
    ));
    let params = (param::Set::builder().uni_count(65_537).try_build())
        .expect("fixture transport parameters");
    assert!(matches!(
        Options::builder()
            .transport(|transport| transport.params(params))
            .try_build(),
        Err(builder::Invalid::PeerUni {
            actual: 65_537,
            minimum: 0,
            maximum: 65_536,
        })
    ));
    let params = (param::Set::builder()
        .bidi_count(65_536)
        .uni_count(65_536)
        .try_build())
    .expect("fixture transport parameters");
    assert!(
        Options::builder()
            .transport(|transport| transport.params(params))
            .streams(|streams| streams.local_bidi(65_536).local_uni(65_536))
            .try_build()
            .is_ok()
    );
}

#[test]
fn packet_journal() {
    assert!(matches!(
        conn::life::options::Journals::default().try_packet(1),
        Err(builder::Invalid::PacketJournal {
            actual: 1,
            minimum: 2,
            maximum: 65_535,
        })
    ));
    assert!(
        conn::life::options::Journals::default()
            .try_packet(2)
            .is_ok()
    );
    assert!(matches!(
        conn::life::options::Journals::default().try_packet(65_536),
        Err(builder::Invalid::PacketJournal {
            actual: 65_536,
            minimum: 2,
            maximum: 65_535,
        })
    ));
}

#[test]
fn crypto_journal() {
    assert!(matches!(
        conn::life::options::Journals::default().try_crypto(0),
        Err(builder::Invalid::CryptoJournal {
            actual: 0,
            minimum: 1,
            maximum: 65_535,
        })
    ));
    assert!(
        conn::life::options::Journals::default()
            .try_crypto(1)
            .is_ok()
    );
    assert!(matches!(
        conn::life::options::Journals::default().try_crypto(65_536),
        Err(builder::Invalid::CryptoJournal {
            actual: 65_536,
            minimum: 1,
            maximum: 65_535,
        })
    ));
}

#[test]
fn control_journal() {
    assert!(matches!(
        conn::life::options::Journals::default().try_control(31),
        Err(builder::Invalid::ControlJournal {
            actual: 31,
            minimum: 32,
            maximum: 65_535,
        })
    ));
    assert!(
        conn::life::options::Journals::default()
            .try_control(32)
            .is_ok()
    );
    assert!(matches!(
        conn::life::options::Journals::default().try_control(65_536),
        Err(builder::Invalid::ControlJournal {
            actual: 65_536,
            minimum: 32,
            maximum: 65_535,
        })
    ));
}

#[test]
fn stream_journal() {
    assert!(matches!(
        conn::life::options::Journals::default().try_stream(31),
        Err(builder::Invalid::StreamJournal {
            actual: 31,
            minimum: 32,
            maximum: 65_535,
        })
    ));
    assert!(
        conn::life::options::Journals::default()
            .try_stream(32)
            .is_ok()
    );
    assert!(matches!(
        conn::life::options::Journals::default().try_stream(65_536),
        Err(builder::Invalid::StreamJournal {
            actual: 65_536,
            minimum: 32,
            maximum: 65_535,
        })
    ));
}

#[test]
fn role_fields() {
    let params = param::Set::default();
    let local = cid::Id::try_from([0x11; 8]).expect("local eight-byte CID");
    let original = cid::Id::try_from([0x22; 8]).expect("original eight-byte CID");
    let retry = cid::Id::try_from([0x33; 8]).expect("retry eight-byte CID");
    let token = [0x44; 16];

    let mut cwire = Vec::with_capacity(param::Codec::MAX_ENCODED_LEN);
    params
        .bind_client(&local)
        .encode(&mut cwire)
        .expect("encode client parameters");
    let client = (param::Codec::decode(&cwire)).expect("fixture transport parameters");
    assert!(client.identity().initial() == Some(&local));
    assert!(client.identity().original().is_none());
    assert!(client.identity().retry().is_none());
    assert_eq!(client.identity().reset(), None);

    let mut swire = Vec::with_capacity(param::Codec::MAX_ENCODED_LEN);
    params
        .bind_server(&local, &original, Some(&retry), Some(&token))
        .encode(&mut swire)
        .expect("encode server parameters");
    let server = (param::Codec::decode(&swire)).expect("fixture transport parameters");
    assert!(server.identity().initial() == Some(&local));
    assert!(server.identity().original() == Some(&original));
    assert!(server.identity().retry() == Some(&retry));
    assert_eq!(server.identity().reset(), Some(token));
}
