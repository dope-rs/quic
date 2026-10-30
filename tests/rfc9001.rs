pub mod common;
use crate::common::{peer, suite::peers::packet::bytes};
use dope_quic::security::qkdf::Initial;
use dope_quic::wire::packet::{self, QUIC_V1};
use long::initial;
use packet::long;
use peer::sealer;

#[test]
fn server_initial_vector() {
    let opener = Initial::try_new(bytes::RFC_DCID)
        .expect("initial derivation")
        .try_server()
        .expect("server key admission");
    let mut sealer = sealer::Raw::initial(bytes::RFC_DCID, rustls::Side::Server, 1)
        .expect("packet number one is inside QUIC's packet-number domain");
    let header = initial::Header {
        version: QUIC_V1,
        dcid: Vec::new(),
        scid: bytes::RFC_SCID.to_vec(),
        token: Vec::new(),
        packet_number: 1,
        pn_len: 2,
    }
    .encode(bytes::RFC_PAYLOAD.len())
    .expect("the RFC server Initial fields and payload length must encode");
    assert_eq!(header.as_bytes(), bytes::RFC_HEADER);
    let header = header.as_bytes();
    let sealed = sealer
        .seal(header, bytes::RFC_PAYLOAD, 1, header.len() - 2, 2)
        .expect("the RFC two-byte packet-number field must seal");
    assert_eq!(sealed.as_slice(), bytes::RFC_WIRE);

    let parsed = long::Parsed::parse(bytes::RFC_WIRE.to_vec())
        .expect("the RFC vector must contain exactly one long-header packet");
    let packet = match parsed {
        long::Parsed::Initial(packet) => Some(packet),
        _ => None,
    }
    .expect("the RFC server Initial must refine to Initial");
    let opened = packet
        .decrypt(&opener, 0)
        .expect("the RFC server Initial key must authenticate the vector");
    assert_eq!(opened.number(), 1);
    assert_eq!(opened.body(), bytes::RFC_PAYLOAD);
}
