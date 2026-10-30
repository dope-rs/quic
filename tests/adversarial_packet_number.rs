use crate::common::peer;
pub mod common;
use common::suite::peers::bounds::{CLIENT_SCID, INITIAL_DCID};
use dope_quic::security::qkdf::Initial;
use dope_quic::wire::packet::{QUIC_V1, long};
use long::initial;
use peer::sealer;

#[test]
fn packet_number_boundary() {
    for (number, width) in [
        (0x71, 1),
        (0x1234, 2),
        (0x123456, 3),
        (0x12345678, 4),
        (1u64 << 32, 4),
        ((1 << 62) - 1, 4),
    ] {
        let opener = Initial::try_new(&INITIAL_DCID)
            .expect("initial derivation")
            .try_client()
            .expect("client key admission");
        let mut sealer = sealer::Raw::initial(&INITIAL_DCID, rustls::Side::Client, number)
            .expect("Initial client secret must form a test sealer");
        let header = initial::Header {
            version: QUIC_V1,
            dcid: INITIAL_DCID.to_vec(),
            scid: CLIENT_SCID.to_vec(),
            token: Vec::new(),
            packet_number: number,
            pn_len: width,
        };
        let payload = vec![0x01; 32];
        let header = header
            .encode(payload.len())
            .expect("bounded Initial header and payload length must encode");
        let header = header.as_bytes();
        let width = usize::from(width);
        let wire = sealer
            .seal(header, &payload, number, header.len() - width, width)
            .expect("valid Initial inputs must seal");
        let packet = {
            match long::Parsed::parse(wire).expect("sealed datagram must contain a long packet") {
                long::Parsed::Initial(packet) => Some(packet),
                _ => None,
            }
            .expect("sealed Initial refined to a 0-RTT packet")
        };
        let opened = packet
            .decrypt(&opener, number)
            .expect("sealed Initial packet must decrypt with matching keys");
        assert_eq!(opened.number(), number);
        assert_eq!(opened.body(), payload);
    }
}

#[test]
fn reserved_bits() {
    let number = 0;
    let header = initial::Header {
        version: QUIC_V1,
        dcid: INITIAL_DCID.to_vec(),
        scid: CLIENT_SCID.to_vec(),
        token: Vec::new(),
        packet_number: number,
        pn_len: 4,
    }
    .encode(1162)
    .expect("bounded Initial header fields must encode");
    assert_eq!(header.as_bytes()[0] & 0x0c, 0);
}
