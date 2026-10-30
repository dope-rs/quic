use crate::common::peer;
pub mod common;

use common::suite::peers::{packet::bytes, tls};
use dope_quic::runtime::routing;
use o3::buffer::storage;
use std::time::Instant;

use dope_quic::conn::life::options;
use dope_quic::security::qkdf::Initial;
use dope_quic::wire::packet::{cid, long};

#[test]
fn initial_uses_one_byte_pn() {
    let (_, key) = peer::raw(0x71).expect("fixed Ed25519 seed must construct");
    let dcid = cid::Id::try_from(bytes::WIDTH_DCID).expect("bounded destination CID");
    let scid = cid::Id::try_from(bytes::WIDTH_SCID).expect("bounded source CID");
    let mut client = tls::client(key)
        .expect("the fixture must admit its native client configuration")
        .connect::<0, Vec<u8>, storage::Shared>(
            dcid,
            scid,
            options::Options::default(),
            routing::Plain,
        )
        .expect("the fixture must construct a client connection");
    let (mut flight, result) = client.with_scope(|mut scope| scope.output().send(Instant::now()));
    result.expect("configured client journals must admit the first Initial");
    assert_eq!(
        flight.len(),
        1,
        "the first client flight must contain one datagram"
    );
    assert_eq!(flight[0].len(), 1_200, "Initial padding remains exact");

    let open = Initial::try_new(&bytes::WIDTH_DCID)
        .expect("initial derivation")
        .try_client()
        .expect("client key admission");
    let parsed = (long::Parsed::parse(flight.remove(0)))
        .expect("the first client datagram must parse as a long-header packet");
    let packet = {
        match parsed {
            long::Parsed::Initial(packet) => Some(packet),
            _ => None,
        }
        .expect("first client packet was zero-RTT")
    };
    let opened = (packet.decrypt(&open, 0))
        .expect("derived Initial keys must authenticate the client packet");
    assert_eq!(opened.number(), 0);
    let (_, head, _) = opened.into_parts();
    let &first =
        (head.first()).expect("a decrypted Initial packet must retain its first header byte");
    assert_eq!(
        (first & 0x03) + 1,
        1,
        "packet-number planning, header encoding, and protection must share the one-byte proof"
    );
}
