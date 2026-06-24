use dope_quic::frame::Frame;
use dope_quic::packet::{HandshakeHeader, InitialHeader, QUIC_V1, ShortHeader};
use dope_quic::packet_protection::PacketProtection;
use dope_quic::qkdf::{InitialSecrets, PacketKeys};
use ring::rand::{SecureRandom, SystemRandom};
use shin::sig::SigningKey;
use shin::{Epoch, Event, client, server};

const INITIAL_DCID: [u8; 8] = [0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce];
const CLIENT_SCID: [u8; 4] = [0xc1, 0xc1, 0xc1, 0xc1];
const SERVER_SCID: [u8; 4] = [0x55, 0x55, 0x55, 0x55];
const TARGET_INITIAL_LEN: usize = 1200;
const TAG_LEN: usize = 16;

fn keys_from_secret(secret: &[u8; 32]) -> PacketProtection {
    PacketProtection::aes_128(&PacketKeys::aes_128(secret))
}

fn extract_send(events: &[Event], epoch: Epoch) -> Option<Vec<u8>> {
    events.iter().find_map(|e| match e {
        Event::Send { epoch: ep, data } if *ep == epoch => Some(data.clone()),
        _ => None,
    })
}

fn extract_keys(events: &[Event], epoch: Epoch) -> Option<([u8; 32], [u8; 32])> {
    events.iter().find_map(|e| match e {
        Event::KeysReady {
            epoch: ep,
            read_secret,
            write_secret,
        } if *ep == epoch => Some((*read_secret, *write_secret)),
        _ => None,
    })
}

fn has_done(events: &[Event]) -> bool {
    events.iter().any(|e| matches!(e, Event::Done))
}

fn build_initial(
    dcid: &[u8],
    scid: &[u8],
    pn: u64,
    crypto_payload: &[u8],
    prot: &PacketProtection,
    pad_to: Option<usize>,
) -> Vec<u8> {
    let mut frames_buf = Vec::with_capacity(crypto_payload.len() + 8);
    Frame::Crypto {
        offset: 0,
        data: crypto_payload.to_vec(),
    }
    .encode(&mut frames_buf);

    let pn_len = 4u8;
    let mut payload = frames_buf;
    if let Some(target) = pad_to {
        let header_estimate = 1 + 4 + 1 + dcid.len() + 1 + scid.len() + 1 + 2;
        let needed = target.saturating_sub(header_estimate + pn_len as usize + TAG_LEN);
        if payload.len() < needed {
            payload.resize(needed, 0);
        }
    }
    let body_len_after_pn = payload.len() + TAG_LEN;

    let h = InitialHeader {
        version: QUIC_V1,
        dcid: dcid.to_vec(),
        scid: scid.to_vec(),
        token: vec![],
        packet_number: pn,
        pn_len,
    };
    let (header_bytes, pn_offset) = h.encode_with_pn(body_len_after_pn);
    prot.encrypt_long(&header_bytes, &payload, pn, pn_offset, pn_len as usize)
}

fn parse_initial(wire: &[u8], prot: &PacketProtection) -> Vec<Frame> {
    let prefix = InitialHeader::decode_pre_hp(wire).expect("Initial header");
    let mut buf = wire.to_vec();
    let body = prot
        .decrypt_long(&mut buf, prefix.pn_offset)
        .expect("Initial decrypt");
    Frame::decode_all(&body).expect("frame decode")
}

fn build_handshake(
    dcid: &[u8],
    scid: &[u8],
    pn: u64,
    crypto_payload: &[u8],
    prot: &PacketProtection,
) -> Vec<u8> {
    let mut frames_buf = Vec::with_capacity(crypto_payload.len() + 8);
    Frame::Crypto {
        offset: 0,
        data: crypto_payload.to_vec(),
    }
    .encode(&mut frames_buf);

    let pn_len = 4u8;
    let body_len_after_pn = frames_buf.len() + TAG_LEN;
    let h = HandshakeHeader {
        version: QUIC_V1,
        dcid: dcid.to_vec(),
        scid: scid.to_vec(),
        packet_number: pn,
        pn_len,
    };
    let (header_bytes, pn_offset) = h.encode_with_pn(body_len_after_pn);
    prot.encrypt_long(&header_bytes, &frames_buf, pn, pn_offset, pn_len as usize)
}

fn parse_handshake(wire: &[u8], prot: &PacketProtection) -> Vec<Frame> {
    let prefix = HandshakeHeader::decode_pre_hp(wire).expect("Handshake header");
    let mut buf = wire.to_vec();
    let body = prot
        .decrypt_long(&mut buf, prefix.pn_offset)
        .expect("Handshake decrypt");
    Frame::decode_all(&body).expect("frame decode")
}

fn extract_crypto_at_zero(frames: &[Frame]) -> Vec<u8> {
    frames
        .iter()
        .find_map(|f| match f {
            Frame::Crypto { offset: 0, data } => Some(data.clone()),
            _ => None,
        })
        .expect("CRYPTO frame at offset 0")
}

fn build_one_rtt_datagram(
    dcid: &[u8],
    pn: u64,
    payload: &[u8],
    prot: &PacketProtection,
) -> Vec<u8> {
    let mut frames_buf = Vec::with_capacity(payload.len() + 8);
    Frame::Datagram {
        length_prefixed: false,
        data: payload.to_vec(),
    }
    .encode(&mut frames_buf);

    let pn_len = 4u8;
    let h = ShortHeader {
        dcid: dcid.to_vec(),
        packet_number: pn,
        pn_len,
    };
    let (header_bytes, pn_offset) = h.encode_with_pn();
    prot.encrypt_short(&header_bytes, &frames_buf, pn, pn_offset, pn_len as usize)
}

fn parse_one_rtt(wire: &[u8], dcid_len: usize, prot: &PacketProtection) -> Vec<Frame> {
    let pn_offset = ShortHeader::pn_offset_for(dcid_len);
    let mut buf = wire.to_vec();
    let body = prot
        .decrypt_short(&mut buf, pn_offset)
        .expect("1-RTT decrypt");
    Frame::decode_all(&body).expect("frame decode")
}

fn extract_datagram(frames: &[Frame]) -> Vec<u8> {
    frames
        .iter()
        .find_map(|f| match f {
            Frame::Datagram { data, .. } => Some(data.clone()),
            _ => None,
        })
        .expect("DATAGRAM frame")
}

#[test]
fn quic_handshake_completes_over_packet_stack() {
    let mut seed = [0u8; 32];
    SystemRandom::new().fill(&mut seed).unwrap();
    let server_signing = SigningKey::from_seed(&seed).unwrap();
    let server_pubkey = *server_signing.pubkey().unwrap();

    let mut server = server::Server::new(server::Config {
        source: shin::server::CertSource::RawPublicKey {
            signing_key: server_signing,
        },
        transport_params: b"server-tp".to_vec(),
        alpn_protocols: Vec::new(),
        ticket_secret: None,
        accept_early_data: false,
    });
    let mut client = client::Client::new(client::Config {
        verifier: shin::client::Verifier::RawPublicKey {
            expected_pubkey: server_pubkey,
        },
        transport_params: b"client-tp".to_vec(),
        alpn_protocols: Vec::new(),
        resumption: None,
        enable_early_data: false,
    });

    let init = InitialSecrets::from_dcid(&INITIAL_DCID);
    let client_initial_w = keys_from_secret(&init.client);
    let client_initial_r = keys_from_secret(&init.server);
    let server_initial_w = keys_from_secret(&init.server);
    let server_initial_r = keys_from_secret(&init.client);

    let c1 = client.start().unwrap();
    let ch = extract_send(&c1, Epoch::Plaintext).expect("CH");
    let wire_ch = build_initial(
        &INITIAL_DCID,
        &CLIENT_SCID,
        0,
        &ch,
        &client_initial_w,
        Some(TARGET_INITIAL_LEN),
    );

    let frames = parse_initial(&wire_ch, &server_initial_r);
    let ch_recovered = extract_crypto_at_zero(&frames);
    assert_eq!(ch_recovered, ch);

    let s1 = server.read(Epoch::Plaintext, &ch_recovered).unwrap();
    let sh = extract_send(&s1, Epoch::Plaintext).expect("SH");
    let s_hs_blob = extract_send(&s1, Epoch::Handshake).expect("server EE+Cert+CV+SF");
    let (s_hs_read, s_hs_write) = extract_keys(&s1, Epoch::Handshake).expect("server hs keys");
    let (s_ap_read, s_ap_write) = extract_keys(&s1, Epoch::Application).expect("server ap keys");

    let server_hs_w = keys_from_secret(&s_hs_write);
    let server_hs_r = keys_from_secret(&s_hs_read);

    let wire_sh = build_initial(&CLIENT_SCID, &SERVER_SCID, 0, &sh, &server_initial_w, None);
    let wire_shs = build_handshake(&CLIENT_SCID, &SERVER_SCID, 0, &s_hs_blob, &server_hs_w);

    let frames = parse_initial(&wire_sh, &client_initial_r);
    let sh_recovered = extract_crypto_at_zero(&frames);
    let c2 = client.read(Epoch::Plaintext, &sh_recovered).unwrap();
    let (c_hs_read, c_hs_write) = extract_keys(&c2, Epoch::Handshake).expect("client hs keys");

    assert_eq!(c_hs_read, s_hs_write);
    assert_eq!(c_hs_write, s_hs_read);

    let client_hs_w = keys_from_secret(&c_hs_write);
    let client_hs_r = keys_from_secret(&c_hs_read);
    let frames = parse_handshake(&wire_shs, &client_hs_r);
    let s_hs_recovered = extract_crypto_at_zero(&frames);
    let c3 = client.read(Epoch::Handshake, &s_hs_recovered).unwrap();
    let (c_ap_read, c_ap_write) = extract_keys(&c3, Epoch::Application).expect("client ap keys");
    let cf = extract_send(&c3, Epoch::Handshake).expect("client Finished");
    assert!(has_done(&c3), "client must emit Done");

    assert_eq!(c_ap_read, s_ap_write);
    assert_eq!(c_ap_write, s_ap_read);

    let wire_cf = build_handshake(&SERVER_SCID, &CLIENT_SCID, 0, &cf, &client_hs_w);

    let frames = parse_handshake(&wire_cf, &server_hs_r);
    let cf_recovered = extract_crypto_at_zero(&frames);
    let s2 = server.read(Epoch::Handshake, &cf_recovered).unwrap();
    assert!(has_done(&s2), "server must emit Done");

    assert!(client.is_done());
    assert!(server.is_done());

    let client_app_w = keys_from_secret(&c_ap_write);
    let client_app_r = keys_from_secret(&c_ap_read);
    let server_app_w = keys_from_secret(&s_ap_write);
    let server_app_r = keys_from_secret(&s_ap_read);

    let dgram_c2s = b"hello server";
    let wire_dg = build_one_rtt_datagram(&SERVER_SCID, 0, dgram_c2s, &client_app_w);
    let frames = parse_one_rtt(&wire_dg, SERVER_SCID.len(), &server_app_r);
    assert_eq!(extract_datagram(&frames), dgram_c2s);

    let dgram_s2c = b"hello client";
    let wire_dg = build_one_rtt_datagram(&CLIENT_SCID, 0, dgram_s2c, &server_app_w);
    let frames = parse_one_rtt(&wire_dg, CLIENT_SCID.len(), &client_app_r);
    assert_eq!(extract_datagram(&frames), dgram_s2c);
}
