pub mod support;

use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, Instant};

use dope_quic::conn::{Handle, stream::Event};
use dope_quic::{Connection, Handler, Mux, transport_params};

const CID: [u8; 8] = [0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42];

#[derive(Default)]
struct Events {
    established: Vec<Handle>,
    datagrams: Vec<(Handle, Vec<u8>)>,
    streams: Vec<(Handle, Event)>,
    closed: Vec<Handle>,
}

#[derive(Clone, Default)]
struct CapturingHandler {
    events: Rc<RefCell<Events>>,
}

impl Handler for CapturingHandler {
    type Connection = Handle;

    fn create_connection(&mut self, _conn: &mut Connection, handle: Handle) -> Handle {
        handle
    }

    fn established(&mut self, connection: &mut Handle, _conn: &mut Connection, h: Handle) {
        assert_eq!(*connection, h);
        self.events.borrow_mut().established.push(h);
    }
    fn datagram(
        &mut self,
        connection: &mut Handle,
        _conn: &mut Connection,
        h: Handle,
        data: Vec<u8>,
    ) {
        assert_eq!(*connection, h);
        self.events.borrow_mut().datagrams.push((h, data.to_vec()));
    }
    fn stream_event(
        &mut self,
        connection: &mut Handle,
        _conn: &mut Connection,
        h: Handle,
        event: Event,
    ) {
        assert_eq!(*connection, h);
        self.events.borrow_mut().streams.push((h, event));
    }
    fn close(&mut self, connection: Handle, h: Handle) {
        assert_eq!(connection, h);
        self.events.borrow_mut().closed.push(h);
    }
}

fn relay_once(
    src: &mut Mux<CapturingHandler>,
    dst: &mut Mux<CapturingHandler>,
    src_addr: SocketAddr,
) -> usize {
    let now = Instant::now();
    let pkts: Vec<_> = src.drain_outgoing().collect();
    let n = pkts.len();
    for mut out in pkts {
        dst.recv(src_addr, out.payload_mut(), now).expect("recv");
    }
    n
}

#[test]
fn quic_datagram_handshake_and_app_traffic() {
    let signing = support::signing_key(0x39);
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
    let mut server = Mux::server(server_handler, signing, user_tp.clone().into()).unwrap();

    let client_handler = CapturingHandler::default();
    let client_events = client_handler.events.clone();
    let mut client = Mux::client(client_handler).unwrap();

    let server_addr: SocketAddr = "10.0.0.2:443".parse().unwrap();
    let client_addr: SocketAddr = "10.0.0.1:50000".parse().unwrap();

    let now = Instant::now();
    let client_handle = client
        .connect(
            server_addr,
            server_pubkey,
            user_tp.into(),
            CID.to_vec(),
            now,
        )
        .unwrap();

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
        .try_send_datagram(client_handle, b"hello server".to_vec(), now)
        .unwrap();
    relay_once(&mut client, &mut server, client_addr);
    {
        let evs = server_events.borrow();
        assert_eq!(evs.datagrams.len(), 1);
        assert_eq!(evs.datagrams[0].0, server_handle);
        assert_eq!(evs.datagrams[0].1, b"hello server");
    }

    server
        .try_send_datagram(server_handle, b"hello client".to_vec(), now)
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
        conn.stream_send(stream_id, b"hello stream").unwrap();
        conn.stream_send_fin(stream_id).unwrap();
        stream_id
    };
    let stream_now = Instant::now();
    client.flush(client_handle, stream_now);
    assert!(relay_once(&mut client, &mut server, client_addr) > 0);
    {
        let evs = server_events.borrow();
        assert!(
            evs.streams
                .contains(&(server_handle, Event::Data { stream_id })),
            "streams={:?} expected handle={:?} stream_id={}",
            evs.streams,
            server_handle,
            stream_id
        );
        assert!(
            evs.streams
                .contains(&(server_handle, Event::Finished { stream_id }))
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
    use dope_quic::varint::VarInt;

    let signing = support::signing_key(0x39);
    let user_tp = transport_params::Params {
        max_idle_timeout_ms: 30_000,
        initial_max_data: 1 << 20,
        ..transport_params::Params::default()
    };
    let mut server = Mux::server(CapturingHandler::default(), signing, user_tp.into()).unwrap();
    assert!(server.set_max_conns(4));

    let now = Instant::now();
    for i in 0u32..16 {
        let dcid = [0xAA, 0xBB, 0xCC, 0xDD, (i >> 8) as u8, i as u8, 0x01, 0x02];
        let scid = [0x10, 0x20, (i >> 8) as u8, i as u8];
        let secrets = InitialSecrets::from_dcid(&dcid).unwrap();
        let keys = PacketKeys::aes_128(&secrets.client).unwrap();
        let prot = PacketProtection::aes_128(&keys).unwrap();
        let mut frames = Vec::new();
        Frame::Crypto {
            offset: VarInt::ZERO,
            data: vec![0u8; 16],
        }
        .encode(&mut frames)
        .unwrap();
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
        let (hdr, pn_off) = h.encode_with_pn(payload.len() + 16).unwrap();
        let mut wire = prot
            .encrypt_long(&hdr, &payload, 0, pn_off, pn_len as usize)
            .unwrap();
        let from: SocketAddr = format!("10.0.0.{}:5000", (i % 250) + 1).parse().unwrap();
        let _ = server.recv(from, &mut wire, now);
    }

    assert_eq!(server.active_conns(), 4, "accept-flood capped at max_conns");
}

#[test]
fn client_egress_stops_at_fixed_capacity_without_dropping_conn_work() {
    let handler = CapturingHandler::default();
    let mut client = Mux::client_with_outgoing_capacity(handler, 2).unwrap();
    let addr: SocketAddr = "10.0.0.2:443".parse().unwrap();
    let handles = (0..4)
        .map(|index| {
            client
                .connect(
                    addr,
                    [7; 32],
                    dope_quic::conn::Config::default(),
                    vec![index as u8; 8],
                    Instant::now(),
                )
                .unwrap()
        })
        .collect::<Vec<_>>();
    assert_eq!(client.outgoing_capacity(), 2);
    assert_eq!(client.outgoing_len(), 2);
    let mut sent = client.drain_outgoing().count();
    for handle in handles {
        client.flush(handle, Instant::now());
        assert!(client.outgoing_len() <= client.outgoing_capacity());
        sent += client.drain_outgoing().count();
    }
    assert!(sent >= 4);
}

#[test]
fn client_egress_byte_budget_uses_encoded_packet_sizes() {
    let addr: SocketAddr = "10.0.0.2:443".parse().unwrap();
    let mut tight =
        Mux::client_with_outgoing_limits(CapturingHandler::default(), 4, 4 * 1200).unwrap();
    for index in 0..4 {
        tight
            .connect(
                addr,
                [7; 32],
                dope_quic::conn::Config::default(),
                vec![index; 8],
                Instant::now(),
            )
            .unwrap();
    }
    assert_eq!(tight.outgoing_len(), 4);
    assert_eq!(tight.outgoing_bytes(), 4 * 1200);

    let mut defaults = Mux::client(CapturingHandler::default()).unwrap();
    for index in 0..300u16 {
        defaults
            .connect(
                addr,
                [7; 32],
                dope_quic::conn::Config::default(),
                index.to_be_bytes().repeat(4),
                Instant::now(),
            )
            .unwrap();
    }
    assert_eq!(defaults.outgoing_capacity(), 4096);
    assert_eq!(defaults.outgoing_len(), 300);
    assert_eq!(defaults.outgoing_bytes(), 300 * 1200);
}

#[test]
fn packet_larger_than_total_byte_capacity_is_rejected() {
    let handler = CapturingHandler::default();
    let events = handler.events.clone();
    let mut client = Mux::client_with_outgoing_limits(handler, 4, 1199).unwrap();
    let error = client.connect(
        "10.0.0.2:443".parse().unwrap(),
        [7; 32],
        dope_quic::conn::Config::default(),
        CID.to_vec(),
        Instant::now(),
    );
    assert_eq!(error, Err(dope_quic::ConnectError::InvalidConfig));
    assert_eq!(client.outgoing_len(), 0);
    assert_eq!(client.outgoing_bytes(), 0);
    assert_eq!(client.active_conns(), 0);
    assert!(events.borrow().closed.is_empty());
}

#[test]
fn thirteen_hundred_byte_cap_round_robins_two_connections() {
    let mut client =
        Mux::client_with_outgoing_limits(CapturingHandler::default(), 2, 1300).unwrap();
    let addr = "10.0.0.2:443".parse().unwrap();
    client
        .connect(
            addr,
            [7; 32],
            dope_quic::conn::Config::default(),
            vec![1; 8],
            Instant::now(),
        )
        .unwrap();
    client
        .connect(
            addr,
            [7; 32],
            dope_quic::conn::Config::default(),
            vec![2; 8],
            Instant::now(),
        )
        .unwrap();
    assert_eq!(client.active_conns(), 2);
    assert_eq!(client.outgoing_len(), 1);
    assert_eq!(client.outgoing_bytes(), 1200);
    let packets = client.drain_outgoing().collect::<Vec<_>>();
    assert_eq!(packets.len(), 2);
    assert!(packets.iter().all(|packet| packet.payload().len() == 1200));
    assert_eq!(client.outgoing_len(), 0);
    assert_eq!(client.outgoing_bytes(), 0);
    assert_eq!(client.active_conns(), 2);
}

#[test]
fn client_connection_capacity_is_fallible() {
    let mut client = Mux::client_with_limits(CapturingHandler::default(), 1, 8, 16 << 10).unwrap();
    let addr = "10.0.0.2:443".parse().unwrap();
    client
        .connect(
            addr,
            [7; 32],
            dope_quic::conn::Config::default(),
            vec![1; 8],
            Instant::now(),
        )
        .unwrap();
    let second = client.connect(
        addr,
        [7; 32],
        dope_quic::conn::Config::default(),
        vec![2; 8],
        Instant::now(),
    );
    assert_eq!(second, Err(dope_quic::ConnectError::Capacity));
}

#[test]
fn reap_shares_global_packet_budget_between_connections() {
    let signing = support::signing_key(9);
    let server_pubkey = *signing.pubkey().unwrap();
    let params = transport_params::Params {
        max_idle_timeout_ms: 30_000,
        initial_max_data: 1 << 20,
        initial_max_stream_data_uni: 1 << 20,
        initial_max_streams_uni: 4,
        ..transport_params::Params::default()
    };
    let server_handler = CapturingHandler::default();
    let server_events = server_handler.events.clone();
    let mut server =
        Mux::server_with_outgoing_capacity(server_handler, signing, params.clone().into(), 10)
            .unwrap();
    let first_handler = CapturingHandler::default();
    let first_events = first_handler.events.clone();
    let second_handler = CapturingHandler::default();
    let second_events = second_handler.events.clone();
    let mut first = Mux::client(first_handler).unwrap();
    let mut second = Mux::client(second_handler).unwrap();
    let server_addr: SocketAddr = "10.0.0.2:443".parse().unwrap();
    let first_addr: SocketAddr = "10.0.0.1:50001".parse().unwrap();
    let second_addr: SocketAddr = "10.0.0.1:50002".parse().unwrap();
    let mut now = Instant::now();
    first
        .connect(
            server_addr,
            server_pubkey,
            params.clone().into(),
            vec![1; 8],
            now,
        )
        .unwrap();
    second
        .connect(server_addr, server_pubkey, params.into(), vec![2; 8], now)
        .unwrap();
    for _ in 0..12 {
        for mut outgoing in first.drain_outgoing().collect::<Vec<_>>() {
            server
                .recv(first_addr, outgoing.payload_mut(), now)
                .unwrap();
        }
        for mut outgoing in second.drain_outgoing().collect::<Vec<_>>() {
            server
                .recv(second_addr, outgoing.payload_mut(), now)
                .unwrap();
        }
        for mut outgoing in server.drain_outgoing().collect::<Vec<_>>() {
            if outgoing.addr() == first_addr {
                first
                    .recv(server_addr, outgoing.payload_mut(), now)
                    .unwrap();
            } else {
                second
                    .recv(server_addr, outgoing.payload_mut(), now)
                    .unwrap();
            }
        }
        now += Duration::from_millis(10);
        if server_events.borrow().established.len() == 2
            && first_events.borrow().established.len() == 1
            && second_events.borrow().established.len() == 1
        {
            break;
        }
    }
    let handles = server_events.borrow().established.clone();
    assert_eq!(handles.len(), 2);
    for handle in handles {
        let conn = server.conn_mut(handle).unwrap();
        let stream = conn.open_uni_stream().unwrap();
        conn.stream_send(stream, &[7; 128 * 1024]).unwrap();
        conn.stream_send_fin(stream).unwrap();
    }
    now += Duration::from_millis(100);
    server.reap_closed(now);
    let destinations = server
        .drain_outgoing()
        .map(|outgoing| outgoing.addr())
        .collect::<Vec<_>>();
    assert!(destinations.len() >= 2);
    assert!(destinations.contains(&first_addr));
    assert!(destinations.contains(&second_addr));
    let first_run = destinations
        .iter()
        .take_while(|&&addr| addr == destinations[0])
        .count();
    assert!(first_run < destinations.len());
}
