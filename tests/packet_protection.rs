pub mod common;
use crate::common::peer;
use dope_quic::security::qkdf::Initial;
use dope_quic::wire::packet::{self, QUIC_V1};
use long::initial;
use packet::long;
use peer::sealer;

#[test]
fn pads_empty_payload() {
    let opener = Initial::try_new(b"minimum-long-payload")
        .expect("initial derivation")
        .try_client()
        .expect("client key admission");
    let mut sealer = sealer::Raw::initial(b"minimum-long-payload", rustls::Side::Client, 0)
        .expect("packet number zero is inside QUIC's packet-number domain");
    let header = initial::Header {
        version: QUIC_V1,
        dcid: b"destination".to_vec(),
        scid: b"source".to_vec(),
        token: Vec::new(),
        packet_number: 0,
        pn_len: 1,
    }
    .encode(0)
    .expect("fixed identifiers and an empty payload must encode");
    let bytes = header.as_bytes();
    let wire = sealer
        .seal(bytes, &[], 0, bytes.len() - 1, 1)
        .expect("a valid one-byte packet-number field must seal");

    let prefix =
        initial::Prefix::decode(&wire).expect("the sealed fixture must retain an Initial prefix");
    assert_eq!(prefix.length, 20);
    let parsed = long::Parsed::parse(wire)
        .expect("the sealed fixture must contain exactly one long-header packet");
    let packet = match parsed {
        long::Parsed::Initial(packet) => Some(packet),
        _ => None,
    }
    .expect("the encoded Initial must refine to Initial");
    let opened = packet
        .decrypt(&opener, 0)
        .expect("matching Initial keys must authenticate the sealed fixture");
    assert_eq!(opened.number(), 0);
    assert_eq!(opened.body(), [0, 0, 0]);
}

#[test]
fn rejects_key_dimensions() {
    use dope_quic::{
        conn,
        conn::life::options::Options,
        security::crypto,
        wire::{frame, frame::close, packet::cid, varint::VarInt},
    };
    use peer::Receiver as _;
    use std::time::Instant;

    let dcid = [0x71; 8];
    for (suite, want_smp, want_tag) in [
        (sealer::Dimensions::<15, 16>::SUITE, 15, 16),
        (sealer::Dimensions::<16, 15>::SUITE, 16, 15),
    ] {
        let peer::Pair {
            mut server,
            mut client,
            mut work,
        } = peer::Pair::try_config(
            Options::default(),
            Options::default(),
            cid::Id::try_from(dcid).expect("fixture connection ID"),
            |config, _| {
                sealer::suite(
                    config,
                    suite.expect("native AES has TLS13 and QUIC support"),
                )
                .expect("the suite retains its native TLS implementation");
            },
        )
        .expect("the advertised suite passes configuration admission");
        let now = Instant::now();
        assert!(matches!(
            server.receive_from(&mut work, &mut client, now),
            Err(peer::Transfer::Input(conn::Error::Crypto(
                crypto::Error::KeyDimensions { sample, tag }
            ))) if sample == want_smp && tag == want_tag
        ));
        assert!(server.view().lifecycle().is_closing());
        let (flight, result) = server.with_scope(|mut scope| scope.output().send(now));
        result.expect("the terminal failure must retain valid Initial protection");
        assert!(!flight.is_empty());
        let opener = Initial::try_new(&dcid)
            .expect("initial derivation")
            .try_server()
            .expect("server key admission");
        let mut closed = false;
        for wire in flight {
            let packet = match long::Parsed::parse(wire)
                .expect("only Initial packets can precede key admission")
            {
                long::Parsed::Initial(packet) => Some(packet),
                _ => None,
            }
            .expect("unadmitted Handshake protection must not publish a packet");
            let opened = packet
                .decrypt(&opener, 0)
                .expect("native Initial protection");
            for frame in frame::Frame::decode_all(opened.body()).expect("terminal close frames") {
                if let frame::View::ConnectionClose { code, .. } = frame.view() {
                    assert!(matches!(code, close::Code::Transport { error_code, .. }
                        if error_code == VarInt::from_u8(0x1)));
                    closed = true;
                }
            }
        }
        assert!(
            closed,
            "bad local key dimensions must close with INTERNAL_ERROR"
        );
    }
}

#[test]
fn encrypt_commits_prefix() {
    use dope_quic::{
        conn::{life::options::Options, output::transmit, wire::packet::Batch},
        security::crypto,
        wire::packet::cid,
    };
    use peer::Receiver as _;
    use std::time::Instant;

    let dcid = [0x71; 8];
    let mut pair = peer::Pair::try_config(
        Options::default(),
        Options::default(),
        cid::Id::try_from(dcid).expect("fixture connection ID"),
        |config, _| {
            sealer::suite(
                config,
                sealer::Dimensions::<16, 16, true>::SUITE
                    .expect("native AES has TLS13 and QUIC support"),
            )
            .expect("the fault fixture retains its native TLS implementation");
        },
    )
    .expect("the native suite passes configuration admission");
    let now = Instant::now();
    pair.server
        .receive_from(&mut pair.work, &mut pair.client, now)
        .expect("valid client Initial must reach the server handshake");
    let mut batch = Batch::default();
    let result = pair
        .server
        .with_scope(|mut scope| scope.output().send_batch(&mut batch, now, 32, 1200));
    assert_eq!(
        result,
        Err(transmit::Error::Admission(transmit::Admission::Protection(
            crypto::Error::HeaderEncrypt(rustls::Error::EncryptError)
        )))
    );
    assert_eq!(batch.packets(), 1);
    let prefix = batch.iter().next().expect("committed Initial packet");
    assert_eq!(batch.byte_len(), prefix.len());
    let opener = Initial::try_new(&dcid)
        .expect("initial derivation")
        .try_server()
        .expect("server key admission");
    let packet = match long::Parsed::parse(prefix.to_vec())
        .expect("committed prefix must remain a complete long packet")
    {
        long::Parsed::Initial(packet) => Some(packet),
        _ => None,
    }
    .expect("committed Initial must survive failed Handshake protection");
    assert_eq!(
        packet
            .decrypt(&opener, 0)
            .expect("committed Initial must retain native protection")
            .number(),
        0
    );
}

#[test]
fn decrypt_keeps_error() {
    use dope_quic::{conn, conn::life::options::Options, security::crypto, wire::packet::cid};
    use peer::Receiver as _;
    use std::time::Instant;

    let mut pair = peer::Pair::try_config(
        Options::default(),
        Options::default(),
        cid::Id::try_from([0x71; 8]).expect("fixture connection ID"),
        |config, _| {
            sealer::suite(
                config,
                sealer::Dimensions::<16, 16, false, true>::SUITE
                    .expect("native AES has TLS13 and QUIC support"),
            )
            .expect("the fault fixture retains its native TLS implementation");
        },
    )
    .expect("the native suite passes configuration admission");
    let now = Instant::now();
    pair.server
        .receive_from(&mut pair.work, &mut pair.client, now)
        .expect("valid client Initial must reach the server handshake");
    pair.client
        .receive_from(&mut pair.work, &mut pair.server, now)
        .expect("valid server flight must reach the client handshake");
    assert!(matches!(
        pair.server
            .receive_from(&mut pair.work, &mut pair.client, now),
        Err(peer::Transfer::Input(conn::Error::Crypto(
            crypto::Error::HeaderDecrypt(rustls::Error::DecryptError)
        )))
    ));
}

#[test]
fn rejects_provider_extent() {
    use dope_quic::{conn, conn::life::options::Options, security::crypto, wire::packet::cid};
    use peer::Receiver as _;
    use std::time::Instant;

    let mut pair = peer::Pair::try_config(
        Options::default(),
        Options::default(),
        cid::Id::try_from([0x71; 8]).expect("fixture connection ID"),
        |config, _| {
            sealer::suite(
                config,
                sealer::Dimensions::<16, 16, false, false, true>::SUITE
                    .expect("native AES has TLS13 and QUIC support"),
            )
            .expect("the fault fixture retains native authentication");
        },
    )
    .expect("the native suite passes configuration admission");
    let now = Instant::now();
    pair.server
        .receive_from(&mut pair.work, &mut pair.client, now)
        .expect("client Initial");
    pair.client
        .receive_from(&mut pair.work, &mut pair.server, now)
        .expect("server flight");
    assert!(matches!(
        pair.server.receive_from(&mut pair.work, &mut pair.client, now),
        Err(peer::Transfer::Input(conn::Error::Crypto(
            crypto::Error::BodyDimensions { actual: 65_536, available }
        ))) if available != 0 && available < 65_536
    ));
    assert!(pair.server.view().lifecycle().is_closing());
}

#[test]
fn errors_in_order() {
    use dope_quic::security::crypto::Error;

    let opener = Initial::try_new(&[])
        .expect("initial derivation")
        .try_client()
        .expect("client key admission");
    let mut sealer = sealer::Raw::initial(&[], rustls::Side::Client, 0)
        .expect("fixed native Initial keys and packet number");
    let header = [0xcc, 0, 0, 0, 1, 0, 0, 0, 49, 0];
    let wire = sealer
        .seal(&header, &[0; 32], 0, 9, 1)
        .expect("fixed Initial header and payload must seal");
    let mut short = header[..9].to_vec();
    short[8] = 19;
    short.resize(28, 0);
    let mut tampered = wire.clone();
    *tampered.last_mut().expect("sealed packet has an AEAD tag") ^= 1;
    for (wire, next, error) in [
        (
            short,
            u64::MAX,
            Error::Sample {
                actual: 28,
                required: 29,
            },
        ),
        (
            wire.clone(),
            u64::MAX,
            Error::Number {
                next: u64::MAX,
                truncated: 0,
                width: 1,
            },
        ),
        (tampered, 0, Error::Decrypt(rustls::Error::DecryptError)),
        (
            wire,
            0,
            Error::ReservedBits {
                actual: 0x0c,
                mask: 0x0c,
            },
        ),
    ] {
        let packet = match long::Parsed::parse(wire)
            .expect("adversarial protection must preserve the long packet layout")
        {
            long::Parsed::Initial(packet) => Some(packet),
            _ => None,
        }
        .expect("the adversarial fixture must remain an Initial");
        assert_eq!(packet.decrypt(&opener, next).err(), Some(error));
    }
}
