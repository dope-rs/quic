use dope_quic::packet::ShortHeader;
use dope_quic::packet_protection::PacketProtection;
use dope_quic::qkdf::{InitialSecrets, PacketKeys};

#[test]
fn in_place_short_protection_matches_copying_path_inside_batch() {
    let secrets = InitialSecrets::from_dcid(b"connection").unwrap();
    let keys = PacketKeys::aes_128(&secrets.client).unwrap();
    let protection = PacketProtection::aes_128(&keys).unwrap();
    let packet_number = 7;
    let (header, pn_offset) = ShortHeader {
        dcid: b"peer-cid".to_vec(),
        packet_number,
        pn_len: 4,
    }
    .encode_with_pn()
    .unwrap();
    let payload = b"stream frame payload";
    let expected = protection
        .encrypt_short(&header, payload, packet_number, pn_offset, 4)
        .unwrap();

    let mut batch = b"previous packet".to_vec();
    let packet_start = batch.len();
    batch.extend_from_slice(&header);
    let payload_start = batch.len();
    batch.extend_from_slice(payload);
    let protected = protection
        .protect_short_in_place(
            &mut batch,
            packet_start,
            payload_start,
            packet_number,
            packet_start + pn_offset,
            4,
        )
        .unwrap();

    assert_eq!(protected, expected.len());
    assert_eq!(&batch[packet_start..], expected);
}
