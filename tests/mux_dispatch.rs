use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Instant;

use dope_quic::{Conn, ConnHandle, Handler, Mux, StreamEvent, transport_params};
use ring::rand::{SecureRandom, SystemRandom};
use shin::sig::SigningKey;

const CID: [u8; 8] = [0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42];

#[derive(Default)]
struct Events {
    established: Vec<ConnHandle>,
    datagrams: Vec<(ConnHandle, Vec<u8>)>,
    streams: Vec<(ConnHandle, StreamEvent)>,
    closed: Vec<ConnHandle>,
}

#[derive(Clone, Default)]
struct CapturingHandler {
    events: Rc<RefCell<Events>>,
}

impl Handler for CapturingHandler {
    fn on_established(&mut self, _conn: &mut Conn, h: ConnHandle) {
        self.events.borrow_mut().established.push(h);
    }
    fn on_datagram(&mut self, _conn: &mut Conn, h: ConnHandle, data: Vec<u8>) {
        self.events.borrow_mut().datagrams.push((h, data.to_vec()));
    }
    fn on_stream_event(&mut self, _conn: &mut Conn, h: ConnHandle, event: StreamEvent) {
        self.events.borrow_mut().streams.push((h, event));
    }
    fn on_close(&mut self, h: ConnHandle) {
        self.events.borrow_mut().closed.push(h);
    }
}

fn relay_once(
    src: &mut Mux<CapturingHandler>,
    dst: &mut Mux<CapturingHandler>,
    src_addr: SocketAddr,
) -> usize {
    let now = Instant::now();
    let pkts = src.pull_outgoing();
    let n = pkts.len();
    for out in pkts {
        dst.on_udp_packet(src_addr, out.payload(), now)
            .expect("recv");
    }
    n
}

#[test]
fn quic_datagram_handshake_and_app_traffic() {
    let mut seed = [0u8; 32];
    SystemRandom::new().fill(&mut seed).unwrap();
    let signing = SigningKey::from_seed(&seed).unwrap();
    let server_pubkey = *signing.pubkey().unwrap();

    let user_tp = transport_params::Params {
        max_idle_timeout_ms: 30_000,
        max_datagram_frame_size: Some(65535),
        initial_max_data: 1 << 20,
        initial_max_stream_data_bidi_local: 1 << 20,
        initial_max_stream_data_bidi_remote: 1 << 20,
        initial_max_stream_data_uni: 1 << 20,
        initial_max_streams_bidi: 8,
        initial_max_streams_uni: 8,
        ..transport_params::Params::default()
    };

    let server_handler = CapturingHandler::default();
    let server_events = server_handler.events.clone();
    let mut server = Mux::server(server_handler, signing, user_tp.clone().into());

    let client_handler = CapturingHandler::default();
    let client_events = client_handler.events.clone();
    let mut client = Mux::client(client_handler);

    let server_addr: SocketAddr = "10.0.0.2:443".parse().unwrap();
    let client_addr: SocketAddr = "10.0.0.1:50000".parse().unwrap();

    let now = Instant::now();
    let client_handle = client.connect(
        server_addr,
        server_pubkey,
        user_tp.into(),
        CID.to_vec(),
        now,
    );

    relay_once(&mut client, &mut server, client_addr);
    relay_once(&mut server, &mut client, server_addr);
    relay_once(&mut client, &mut server, client_addr);

    let server_handle = {
        let evs = server_events.borrow();
        assert_eq!(evs.established.len(), 1, "server got Established");
        evs.established[0]
    };
    {
        let evs = client_events.borrow();
        assert_eq!(evs.established.len(), 1, "client got Established");
        assert_eq!(evs.established[0], client_handle);
    }

    client
        .send_datagram(client_handle, b"hello server".to_vec(), now)
        .unwrap();
    relay_once(&mut client, &mut server, client_addr);
    {
        let evs = server_events.borrow();
        assert_eq!(evs.datagrams.len(), 1);
        assert_eq!(evs.datagrams[0].0, server_handle);
        assert_eq!(evs.datagrams[0].1, b"hello server");
    }

    server
        .send_datagram(server_handle, b"hello client".to_vec(), now)
        .unwrap();
    relay_once(&mut server, &mut client, server_addr);
    {
        let evs = client_events.borrow();
        assert_eq!(evs.datagrams.len(), 1);
        assert_eq!(evs.datagrams[0].0, client_handle);
        assert_eq!(evs.datagrams[0].1, b"hello client");
    }

    let stream_id = {
        let conn = client.conn_mut(client_handle).expect("client conn");
        let stream_id = conn.open_bidi_stream().unwrap();
        conn.stream_send(stream_id, b"hello stream");
        conn.stream_send_fin(stream_id);
        stream_id
    };
    let stream_now = Instant::now();
    client.flush(client_handle, stream_now);
    assert!(relay_once(&mut client, &mut server, client_addr) > 0);
    {
        let evs = server_events.borrow();
        assert!(
            evs.streams
                .contains(&(server_handle, StreamEvent::Data { stream_id })),
            "streams={:?} expected handle={:?} stream_id={}",
            evs.streams,
            server_handle,
            stream_id
        );
        assert!(
            evs.streams
                .contains(&(server_handle, StreamEvent::Finished { stream_id }))
        );
    }

    client.close(client_handle);
    assert_eq!(client_events.borrow().closed, vec![client_handle]);
}

#[test]
fn accept_flood_is_bounded_by_max_conns() {
    use dope_quic::frame::Frame;
    use dope_quic::packet::{InitialHeader, QUIC_V1};
    use dope_quic::packet_protection::PacketProtection;
    use dope_quic::qkdf::{InitialSecrets, PacketKeys};

    let mut seed = [0u8; 32];
    SystemRandom::new().fill(&mut seed).unwrap();
    let signing = SigningKey::from_seed(&seed).unwrap();
    let user_tp = transport_params::Params {
        max_idle_timeout_ms: 30_000,
        initial_max_data: 1 << 20,
        ..transport_params::Params::default()
    };
    let mut server = Mux::server(CapturingHandler::default(), signing, user_tp.into());
    server.set_max_conns(4);

    let now = Instant::now();
    for i in 0u32..16 {
        let dcid = [0xAA, 0xBB, 0xCC, 0xDD, (i >> 8) as u8, i as u8, 0x01, 0x02];
        let scid = [0x10, 0x20, (i >> 8) as u8, i as u8];
        let secrets = InitialSecrets::from_dcid(&dcid);
        let prot = PacketProtection::aes_128(&PacketKeys::aes_128(&secrets.client));
        let mut frames = Vec::new();
        Frame::Crypto {
            offset: 0,
            data: vec![0u8; 16],
        }
        .encode(&mut frames);
        let pn_len = 4u8;
        let mut payload = frames;
        if payload.len() < 1162 {
            payload.resize(1162, 0);
        }
        let h = InitialHeader {
            version: QUIC_V1,
            dcid: dcid.to_vec(),
            scid: scid.to_vec(),
            token: vec![],
            packet_number: 0,
            pn_len,
        };
        let (hdr, pn_off) = h.encode_with_pn(payload.len() + 16);
        let wire = prot.encrypt_long(&hdr, &payload, 0, pn_off, pn_len as usize);
        let from: SocketAddr = format!("10.0.0.{}:5000", (i % 250) + 1).parse().unwrap();
        let _ = server.on_udp_packet(from, &wire, now);
    }

    assert_eq!(server.active_conns(), 4, "accept-flood capped at max_conns");
}
