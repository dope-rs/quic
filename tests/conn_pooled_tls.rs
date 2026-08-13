use std::time::Instant;

use dope_quic::conn::{self, setup, tls};
use dope_quic::packet::ConnectionId;
use dope_quic::varint::VarInt;
use dope_quic::{ConnectError, transport_params};
use shin::crypto::sig::SigningKey;
use shin::server::{
    Shard,
    config::{CertSource, Config, NoClientAuth, NoGuard},
};

const CID: [u8; 8] = [0x42; 8];

fn cid() -> ConnectionId {
    ConnectionId::try_from(CID.as_slice()).unwrap()
}

type ServerConnection<'pool> = tls::ServerConnection<'pool, NoGuard, NoClientAuth>;

#[test]
fn transport_parameter_reservation_is_the_exact_valid_all_fields_bound() {
    let maximum = transport_params::Params {
        max_idle_timeout_ms: VarInt::MAX,
        max_udp_payload_size: VarInt::MAX,
        initial_max_data: VarInt::MAX,
        initial_max_stream_data_bidi_local: VarInt::MAX,
        initial_max_stream_data_bidi_remote: VarInt::MAX,
        initial_max_stream_data_uni: VarInt::MAX,
        initial_max_streams_bidi: 1 << 60,
        initial_max_streams_uni: 1 << 60,
        ack_delay_exponent: 20,
        max_ack_delay_ms: (1 << 14) - 1,
        disable_active_migration: true,
        active_connection_id_limit: VarInt::MAX,
        initial_source_connection_id: Some(ConnectionId::try_from(&[0; 20][..]).unwrap()),
        original_destination_connection_id: Some(ConnectionId::try_from(&[0; 20][..]).unwrap()),
        retry_source_connection_id: Some(ConnectionId::try_from(&[0; 20][..]).unwrap()),
        max_datagram_frame_size: Some(VarInt::MAX),
        stateless_reset_token: Some([0; 16]),
    };
    let mut encoded = Vec::with_capacity(transport_params::Params::MAX_ENCODED_LEN);

    maximum.encode(&mut encoded).unwrap();

    assert_eq!(encoded.len(), transport_params::Params::MAX_ENCODED_LEN);
    assert_eq!(
        encoded.capacity(),
        transport_params::Params::MAX_ENCODED_LEN
    );
}

fn options() -> conn::config::Options {
    transport_params::Params {
        max_idle_timeout_ms: 30_000,
        ..Default::default()
    }
    .into()
}

fn server_connection<'pool>(
    pool: &'pool tls::ServerPool,
) -> Result<ServerConnection<'pool>, ConnectError> {
    setup::Server::accept_pooled(
        conn::server::Ids::initial(cid(), cid(), cid()),
        options(),
        pool,
    )
}

#[test]
fn pooled_authority_rejects_connection_local_tls_configuration() {
    let signing_key = SigningKey::from_seed(&[0x73; 32]).unwrap();
    let server_pubkey = *signing_key.pubkey().unwrap();
    let shard = Shard::new(Config {
        source: CertSource::RawPublicKey { signing_key },
        alpn_protocols: Vec::new(),
        ticket_keys: None,
    })
    .unwrap();
    let server_pool = tls::server_pool(&shard, 1).unwrap();
    let client_pool = tls::ClientPool::new(server_pubkey, Vec::new(), false, None, 1).unwrap();

    let mut client_options = options();
    client_options.alpn_protocols.push(b"duplicate".to_vec());
    assert_eq!(
        setup::Client::<0>::connect_pooled(
            CID.to_vec(),
            CID.to_vec(),
            &client_pool,
            client_options,
        )
        .err(),
        Some(ConnectError::InvalidConfig)
    );

    let mut server_options = options();
    server_options.ticket_secret = Some([0x51; 32]);
    assert_eq!(
        setup::Server::accept_pooled(
            conn::server::Ids::initial(cid(), cid(), cid()),
            server_options,
            &server_pool,
        )
        .err(),
        Some(ConnectError::InvalidConfig)
    );
}

fn transfer_client_to_server(
    client: &mut tls::Connection<'_>,
    server: &mut ServerConnection<'_>,
    workspace: &mut conn::ReceiveWorkspace,
    now: Instant,
) {
    for mut packet in client.transmit().send(now) {
        server.recv_packet(workspace, &mut packet, now).unwrap();
    }
}

fn transfer_server_to_client(
    server: &mut ServerConnection<'_>,
    client: &mut tls::Connection<'_>,
    workspace: &mut conn::ReceiveWorkspace,
    now: Instant,
) {
    for mut packet in server.transmit().send(now) {
        client.recv_packet(workspace, &mut packet, now).unwrap();
    }
}

#[test]
fn one_slot_tls_pools_recycle_after_handshake_while_connections_stay_live() {
    let signing_key = SigningKey::from_seed(&[0x39; 32]).unwrap();
    let server_pubkey = *signing_key.pubkey().unwrap();
    let shard = Shard::new(Config {
        source: CertSource::RawPublicKey { signing_key },
        alpn_protocols: Vec::new(),
        ticket_keys: None,
    })
    .unwrap();
    let server_pool = tls::server_pool(&shard, 1).unwrap();
    let client_pool = tls::ClientPool::new(server_pubkey, Vec::new(), false, None, 1).unwrap();

    assert_eq!(client_pool.capacity_profile().0, 0);
    assert_eq!(
        client_pool.capacity_profile().2,
        transport_params::Params::MAX_ENCODED_LEN
    );
    assert_eq!(server_pool.capacities().0, 0);
    assert_eq!(
        server_pool.capacities().3,
        transport_params::Params::MAX_ENCODED_LEN
    );

    let mut server = server_connection(&server_pool).unwrap();
    let mut client =
        setup::Client::<0>::connect_pooled(CID.to_vec(), CID.to_vec(), &client_pool, options())
            .unwrap();

    assert_eq!(
        setup::Client::<0>::connect_pooled(CID.to_vec(), CID.to_vec(), &client_pool, options(),)
            .err(),
        Some(ConnectError::Capacity)
    );
    assert_eq!(
        server_connection(&server_pool).err(),
        Some(ConnectError::Capacity)
    );

    let now = Instant::now();
    let mut server_receive = conn::ReceiveWorkspace::new();
    let mut client_receive = conn::ReceiveWorkspace::new();
    for _ in 0..6 {
        transfer_client_to_server(&mut client, &mut server, &mut server_receive, now);
        transfer_server_to_client(&mut server, &mut client, &mut client_receive, now);
    }
    assert!(client.status().is_established());
    assert!(server.status().is_established());

    let second_client =
        setup::Client::<0>::connect_pooled(CID.to_vec(), CID.to_vec(), &client_pool, options())
            .unwrap();
    let second_server = server_connection(&server_pool).unwrap();

    drop((second_client, second_server, client, server));
}
