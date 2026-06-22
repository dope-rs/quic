use dope_quic::packet::{DecodedInitialPrefix, InitialHeader};

#[test]
fn initial_header_encode_matches_rfc9001_a2_plain_header() {
    const EXPECTED: [u8; 22] = [
        0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0x00,
        0x00, 0x44, 0x9e, 0x00, 0x00, 0x00, 0x02,
    ];
    let h = InitialHeader {
        version: dope_quic::packet::QUIC_V1,
        dcid: vec![0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08],
        scid: vec![],
        token: vec![],
        packet_number: 2,
        pn_len: 4,
    };
    let (buf, pn_off) = h.encode_with_pn(1178);
    assert_eq!(pn_off, 18);
    assert_eq!(buf, EXPECTED);
}

#[test]
fn initial_header_round_trip() {
    let h = InitialHeader {
        version: dope_quic::packet::QUIC_V1,
        dcid: vec![1, 2, 3, 4, 5, 6, 7, 8],
        scid: vec![9, 10, 11, 12],
        token: vec![0xaa, 0xbb, 0xcc],
        packet_number: 17,
        pn_len: 2,
    };
    let body_len_after_pn = 100;
    let (buf, pn_off) = h.encode_with_pn(body_len_after_pn);

    let prefix = InitialHeader::decode_pre_hp(&buf).unwrap();
    assert_eq!(
        prefix,
        DecodedInitialPrefix {
            version: dope_quic::packet::QUIC_V1,
            dcid: h.dcid.clone(),
            scid: h.scid.clone(),
            token: h.token.clone(),
            pn_offset: pn_off,
            length: h.pn_len as usize + body_len_after_pn,
        }
    );
}

#[test]
fn decode_pre_hp_rejects_short_header_form() {
    let mut buf = [0u8; 32];
    buf[0] = 0x40;
    assert!(InitialHeader::decode_pre_hp(&buf).is_err());
}

#[test]
fn decode_pre_hp_rejects_unknown_version() {
    let mut buf = vec![0xc0, 0xff, 0xff, 0xff, 0xff, 0, 0, 0];
    buf.resize(20, 0);
    assert!(InitialHeader::decode_pre_hp(&buf).is_err());
}
