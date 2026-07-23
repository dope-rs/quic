use dope_quic::packet::{InitialHeader, QUIC_V1};
use dope_quic::packet_protection::PacketProtection;
use dope_quic::qkdf::{InitialSecrets, PacketKeys};
use dope_quic::{Conn, ServerConn, conn, transport_params};
use shin::server::{ClientCertVerifier, EarlyDataGuard};
use shin::sig::SigningKey;
use std::time::Instant;

pub fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_seed(&[seed; 32]).unwrap()
}

pub fn config() -> conn::Config {
    config_with_credit(1 << 20, 1 << 20, 8, 8)
}

pub fn config_with_credit(
    stream_credit: u64,
    connection_credit: u64,
    bidi_streams: u64,
    uni_streams: u64,
) -> conn::Config {
    conn::Config {
        transport_params: transport_params::Params {
            max_idle_timeout_ms: 30_000,
            max_datagram_frame_size: Some(65_535),
            active_connection_id_limit: 8,
            initial_max_data: connection_credit,
            initial_max_stream_data_bidi_local: stream_credit,
            initial_max_stream_data_bidi_remote: stream_credit,
            initial_max_stream_data_uni: stream_credit,
            initial_max_streams_bidi: bidi_streams,
            initial_max_streams_uni: uni_streams,
            ..Default::default()
        },
        ..Default::default()
    }
}

pub trait Receiver {
    fn receive(&mut self, packet: &[u8], now: Instant);
}

impl Receiver for Conn {
    fn receive(&mut self, packet: &[u8], now: Instant) {
        self.recv_packet(packet, now).unwrap();
    }
}

impl<G, V> Receiver for ServerConn<G, V>
where
    G: EarlyDataGuard,
    V: ClientCertVerifier,
{
    fn receive(&mut self, packet: &[u8], now: Instant) {
        self.recv_packet(packet, now).unwrap();
    }
}

pub fn connected_pair() -> (ServerConn, Conn) {
    connected_pair_with(config(), config())
}

pub fn connected_pair_with(
    server_config: conn::Config,
    client_config: conn::Config,
) -> (ServerConn, Conn) {
    let cid = vec![0x71; 8];
    let signing = signing_key(0x39);
    let public_key = *signing.pubkey().unwrap();
    let mut server = Conn::new_server(
        cid.clone(),
        cid.clone(),
        cid.clone(),
        signing,
        server_config,
    )
    .unwrap();
    let mut client = Conn::new_client(cid.clone(), cid, public_key, client_config).unwrap();
    let now = Instant::now();
    for _ in 0..6 {
        transfer(&mut client, &mut server, now);
        transfer(&mut server, &mut client, now);
    }
    assert!(client.is_established() && server.is_established());
    (server, client)
}

pub fn transfer<R: Receiver>(from: &mut Conn, into: &mut R, now: Instant) {
    for packet in from.send_packets(now) {
        into.receive(&packet, now);
    }
}

pub fn client_initial(dcid: &[u8], scid: &[u8], packet_number: u64, frames: &[u8]) -> Vec<u8> {
    let secrets = InitialSecrets::from_dcid(dcid).unwrap();
    let keys = PacketKeys::aes_128(&secrets.client).unwrap();
    let protection = PacketProtection::aes_128(&keys).unwrap();
    let mut payload = frames.to_vec();
    loop {
        let header = InitialHeader {
            version: QUIC_V1,
            dcid: dcid.to_vec(),
            scid: scid.to_vec(),
            token: Vec::new(),
            packet_number,
            pn_len: 4,
        };
        let (encoded, pn_offset) = header.encode_with_pn(payload.len() + 16).unwrap();
        let total = encoded.len() + payload.len() + 16;
        if total >= 1200 {
            return protection
                .encrypt_long(&encoded, &payload, packet_number, pn_offset, 4)
                .unwrap();
        }
        payload.resize(payload.len() + 1200 - total, 0);
    }
}
