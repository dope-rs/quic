use dope_quic::frame::Frame;
use dope_quic::packet::{InitialHeader, QUIC_V1};
use dope_quic::packet_protection::PacketProtection;
use dope_quic::qkdf::{InitialSecrets, PacketKeys};

const TARGET_LEN: usize = 1200;
const TAG_LEN: usize = 16;

fn build_client_initial(
    initial_dcid: &[u8],
    client_scid: &[u8],
    pn: u64,
    crypto_payload: &[u8],
) -> Vec<u8> {
    let secrets = InitialSecrets::from_dcid(initial_dcid);
    let prot = PacketProtection::aes_128(&PacketKeys::aes_128(&secrets.client));

    let mut frames_buf = Vec::with_capacity(crypto_payload.len() + 8);
    Frame::Crypto {
        offset: 0,
        data: crypto_payload.to_vec(),
    }
    .encode(&mut frames_buf);

    let pn_len = 4u8;
    let mut payload = frames_buf;
    let header_len_estimate = 1 + 4 + 1 + initial_dcid.len() + 1 + client_scid.len() + 1 + 2;
    let needed_payload = TARGET_LEN.saturating_sub(header_len_estimate + pn_len as usize + TAG_LEN);
    if payload.len() < needed_payload {
        payload.resize(needed_payload, 0);
    }
    let body_len_after_pn = payload.len() + TAG_LEN;

    let h = InitialHeader {
        version: QUIC_V1,
        dcid: initial_dcid.to_vec(),
        scid: client_scid.to_vec(),
        token: vec![],
        packet_number: pn,
        pn_len,
    };
    let (header_bytes, pn_offset) = h.encode_with_pn(body_len_after_pn);

    prot.encrypt_long(&header_bytes, &payload, pn, pn_offset, pn_len as usize)
}

#[test]
fn server_recovers_crypto_payload_from_client_initial() {
    let initial_dcid: [u8; 8] = [0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce];
    let client_scid: [u8; 4] = [0x01, 0x02, 0x03, 0x04];
    let pn = 0u64;
    let ch_bytes = b"PRETEND-CLIENT-HELLO-BYTES-FROM-SHIN";

    let mut wire = build_client_initial(&initial_dcid, &client_scid, pn, ch_bytes);
    assert_eq!(wire.len(), TARGET_LEN);

    let prefix = InitialHeader::decode_pre_hp(&wire).expect("parse header");
    assert_eq!(prefix.dcid, initial_dcid);
    assert_eq!(prefix.scid, client_scid);

    let secrets = InitialSecrets::from_dcid(&initial_dcid);
    let server_prot = PacketProtection::aes_128(&PacketKeys::aes_128(&secrets.client));
    let body = server_prot
        .decrypt_long(&mut wire, prefix.pn_offset)
        .expect("server decrypt");

    let frames = Frame::decode_all(&body).expect("decode frames");
    let recovered = frames
        .iter()
        .find_map(|f| match f {
            Frame::Crypto { offset: 0, data } => Some(data.clone()),
            _ => None,
        })
        .expect("CRYPTO frame at offset 0");
    assert_eq!(recovered, ch_bytes);
}
