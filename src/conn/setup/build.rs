use core::array;
use std::{collections, time};

use shin::client;

use crate::clock;
use crate::conn;
use crate::errors;
use crate::new_reno;
use crate::packet;
use crate::packet_protection;
use crate::qkdf;
use crate::secrets;
use crate::transport_params;

fn local_tp_bytes(
    is_client: bool,
    local_cid: &packet::ConnectionId,
    original_dcid: &packet::ConnectionId,
    retry_scid: Option<&packet::ConnectionId>,
    user_parameters: transport_params::Params,
) -> Result<Vec<u8>, errors::ConnectFailure> {
    let mut parameters = user_parameters;
    parameters.initial_source_connection_id = Some(*local_cid);
    if !is_client {
        parameters.original_destination_connection_id = Some(*original_dcid);
        if let Some(source_id) = retry_scid {
            parameters.retry_source_connection_id = Some(*source_id);
        }
    }
    let mut encoded = Vec::new();
    parameters
        .encode(&mut encoded)
        .map_err(|_| errors::ConnectFailure::InvalidConfig)?;
    Ok(encoded)
}

enum Side<'a, G, V, const DOMAIN: u8>
where
    G: shin::server::config::EarlyDataGuard,
    V: shin::server::config::ClientCertVerifier,
{
    Client {
        server_pubkey: [u8; 32],
    },
    ClientPooled {
        pool: &'a conn::tls::ClientPool,
    },
    Server {
        peer_cid: packet::ConnectionId,
        shard: &'a shin::server::Shard<G, V, DOMAIN>,
    },
    ServerPooled {
        peer_cid: packet::ConnectionId,
        pool: &'a shin::server::workspace::QuicPool<conn::handshake::Clock, V, DOMAIN, G>,
    },
}

pub(crate) struct Builder<'a, G, V, const DOMAIN: u8>
where
    G: shin::server::config::EarlyDataGuard,
    V: shin::server::config::ClientCertVerifier,
{
    initial_dcid: packet::ConnectionId,
    local_cid: packet::ConnectionId,
    original_dcid: packet::ConnectionId,
    retry_scid: Option<packet::ConnectionId>,
    options: conn::config::Options,
    side: Side<'a, G, V, DOMAIN>,
}

pub(crate) enum Built<'pool, G, V, const DOMAIN: u8, B>
where
    G: shin::server::config::EarlyDataGuard,
    V: shin::server::config::ClientCertVerifier,
    B: crate::stream::ReceiveBuffer,
{
    Client(conn::session::Connection<DOMAIN, B>),
    ClientPooled {
        connection: conn::session::Connection<DOMAIN, B>,
        tls: conn::handshake::ClientTls<'pool>,
    },
    Server {
        connection: conn::session::Connection<DOMAIN, B>,
        tls: Box<shin::server::QuicConnection<conn::handshake::Clock, DOMAIN, G, V>>,
    },
    ServerPooled {
        connection: conn::session::Connection<DOMAIN, B>,
        tls: shin::server::QuicPooledConnection<'pool, conn::handshake::Clock, DOMAIN, V, G>,
    },
}

type OwnedServerTls<G, V, const DOMAIN: u8> =
    shin::server::QuicConnection<conn::handshake::Clock, DOMAIN, G, V>;
type OwnedServerParts<G, V, const DOMAIN: u8, B> = (
    conn::session::Connection<DOMAIN, B>,
    Box<OwnedServerTls<G, V, DOMAIN>>,
);

impl<'pool, G, V, const DOMAIN: u8, B> Built<'pool, G, V, DOMAIN, B>
where
    G: shin::server::config::EarlyDataGuard,
    V: shin::server::config::ClientCertVerifier,
    B: crate::stream::ReceiveBuffer,
{
    pub(crate) fn into_server(self) -> Option<OwnedServerParts<G, V, DOMAIN, B>> {
        match self {
            Self::Server { connection, tls } => Some((connection, tls)),
            Self::Client(_) | Self::ClientPooled { .. } | Self::ServerPooled { .. } => None,
        }
    }
}

impl<'a, G, V, const DOMAIN: u8> Builder<'a, G, V, DOMAIN>
where
    G: shin::server::config::EarlyDataGuard,
    V: shin::server::config::ClientCertVerifier,
{
    pub(super) fn client(
        initial_dcid: packet::ConnectionId,
        local_cid: packet::ConnectionId,
        server_pubkey: [u8; 32],
        options: conn::config::Options,
    ) -> Self {
        let original_dcid = initial_dcid;
        Self {
            initial_dcid,
            local_cid,
            original_dcid,
            retry_scid: None,
            options,
            side: Side::Client { server_pubkey },
        }
    }

    pub(super) fn client_pooled(
        initial_dcid: packet::ConnectionId,
        local_cid: packet::ConnectionId,
        pool: &'a conn::tls::ClientPool,
        options: conn::config::Options,
    ) -> Self {
        let original_dcid = initial_dcid;
        Self {
            initial_dcid,
            local_cid,
            original_dcid,
            retry_scid: None,
            options,
            side: Side::ClientPooled { pool },
        }
    }

    pub(crate) fn server(
        ids: conn::server::Ids,
        options: conn::config::Validated,
        shard: &'a shin::server::Shard<G, V, DOMAIN>,
    ) -> Self {
        let conn::server::Ids {
            initial_dcid,
            local_cid,
            peer_cid,
            tp_original_dcid,
            retry_scid,
        } = ids;
        Self {
            initial_dcid,
            local_cid,
            original_dcid: tp_original_dcid,
            retry_scid,
            options: options.into_inner(),
            side: Side::Server { peer_cid, shard },
        }
    }

    pub(crate) fn server_pooled(
        ids: conn::server::Ids,
        options: conn::config::Validated,
        pool: &'a shin::server::workspace::QuicPool<conn::handshake::Clock, V, DOMAIN, G>,
    ) -> Self {
        let conn::server::Ids {
            initial_dcid,
            local_cid,
            peer_cid,
            tp_original_dcid,
            retry_scid,
        } = ids;
        Self {
            initial_dcid,
            local_cid,
            original_dcid: tp_original_dcid,
            retry_scid,
            options: options.into_inner(),
            side: Side::ServerPooled { peer_cid, pool },
        }
    }

    pub(crate) fn finish<B: crate::stream::ReceiveBuffer>(
        self,
    ) -> Result<Built<'a, G, V, DOMAIN, B>, errors::ConnectFailure> {
        let Self {
            initial_dcid,
            local_cid,
            original_dcid,
            retry_scid,
            options,
            side,
        } = self;
        let conn::config::Options {
            transport_params: mut user_tp,
            datagram_congestion_control,
            pending_datagrams_capacity,
            incoming_datagrams_capacity,
            stream_events_capacity,
            receive_segment_capacity,
            packet_journal_capacity,
            crypto_journal_capacity,
            control_journal_capacity,
            stream_journal_capacity,
            local_bidi_stream_capacity,
            local_uni_stream_capacity,
            cid_prefix,
            stateless_reset_secret,
            require_address_validation: _,
            retry_token_secret: _,
            ticket_secret: _,
            resumption,
            enable_early_data,
            resumption_peer_tp,
            alpn_protocols,
            server_cert_chain: _,
            identity,
            max_pmtu,
        } = options;
        let secrets = qkdf::InitialSecrets::from_dcid(&initial_dcid)
            .map_err(|_| errors::ConnectFailure::InvalidConfig)?;
        let local_idle = time::Duration::from_millis(user_tp.max_idle_timeout_ms);
        let local_max_data = user_tp.initial_max_data;
        let local_initial_max_stream_data_bidi_local = user_tp.initial_max_stream_data_bidi_local;
        let local_initial_max_stream_data_bidi_remote = user_tp.initial_max_stream_data_bidi_remote;
        let local_initial_max_stream_data_uni = user_tp.initial_max_stream_data_uni;
        let local_initial_max_streams_bidi = user_tp.initial_max_streams_bidi;
        let local_initial_max_streams_uni = user_tp.initial_max_streams_uni;
        let local_active_connection_id_limit = user_tp.active_connection_id_limit;

        enum Tls<'pool, G, V, const DOMAIN: u8>
        where
            G: shin::server::config::EarlyDataGuard,
            V: shin::server::config::ClientCertVerifier,
        {
            Client(conn::handshake::ClientTls<'pool>),
            Server(Box<shin::server::QuicConnection<conn::handshake::Clock, DOMAIN, G, V>>),
            ServerPooled(
                shin::server::QuicPooledConnection<'pool, conn::handshake::Clock, DOMAIN, V, G>,
            ),
            None,
        }

        let (handshake, tls, is_client, peer_cid, peer_first_scid, peer_address_validated) =
            match side {
                Side::Client { server_pubkey } => {
                    user_tp.stateless_reset_token = None;
                    let tp_bytes = local_tp_bytes(
                        true,
                        &local_cid,
                        &original_dcid,
                        retry_scid.as_ref(),
                        user_tp,
                    )?;
                    let cfg = client::config::Config {
                        verifier: client::config::Verifier::RawPublicKey {
                            expected_pubkey: server_pubkey,
                        },
                        transport_params: tp_bytes,
                        alpn_protocols,
                        enable_early_data,
                    };
                    let template = cfg
                        .try_into_template_with_transport(shin::transport::Mode::Quic)
                        .map_err(errors::ConnectFailure::InvalidTlsConfig)?;
                    let prepared = match resumption {
                        Some(ticket) => template
                            .restore(
                                ticket
                                    .into_restore()
                                    .map_err(errors::ConnectFailure::InvalidTlsConfig)?,
                            )
                            .map_err(errors::ConnectFailure::InvalidTlsConfig)?,
                        None => template.without_resumption(),
                    };
                    let identity = identity
                        .map(shin::client::config::Identity::try_into_template)
                        .transpose()
                        .map_err(errors::ConnectFailure::InvalidTlsConfig)?;
                    let client = prepared.into_framed_client(
                        identity,
                        clock::WallClock::now_millis as conn::handshake::Clock,
                    );
                    let outbound_layout = client
                        .outbound_layout()
                        .map_err(|_| errors::ConnectFailure::Tls)?;
                    let initial_write = packet_protection::PacketProtection::aes_128(
                        &qkdf::PacketKeys::aes_128(&secrets.client)
                            .map_err(|_| errors::ConnectFailure::InvalidConfig)?,
                    )
                    .map_err(|_| errors::ConnectFailure::InvalidConfig)?;
                    let initial_read = packet_protection::PacketProtection::aes_128(
                        &qkdf::PacketKeys::aes_128(&secrets.server)
                            .map_err(|_| errors::ConnectFailure::InvalidConfig)?,
                    )
                    .map_err(|_| errors::ConnectFailure::InvalidConfig)?;
                    (
                        conn::handshake::Handshake::client(
                            client,
                            initial_read,
                            initial_write,
                            crypto_journal_capacity,
                            outbound_layout,
                        ),
                        Tls::None,
                        true,
                        initial_dcid,
                        None,
                        true,
                    )
                }
                Side::ClientPooled { pool } => {
                    user_tp.stateless_reset_token = None;
                    let mut reservation = pool.reserve(resumption)?;
                    user_tp
                        .encode_connection_retained(
                            true,
                            &local_cid,
                            &original_dcid,
                            retry_scid.as_deref(),
                            &mut reservation.transport_params(),
                        )
                        .map_err(|_| errors::ConnectFailure::InvalidConfig)?;
                    let client =
                        reservation.connect(clock::WallClock::now_millis as conn::handshake::Clock);
                    let outbound_layout = client
                        .outbound_layout()
                        .map_err(|_| errors::ConnectFailure::Tls)?;
                    let initial_write = packet_protection::PacketProtection::aes_128(
                        &qkdf::PacketKeys::aes_128(&secrets.client)
                            .map_err(|_| errors::ConnectFailure::InvalidConfig)?,
                    )
                    .map_err(|_| errors::ConnectFailure::InvalidConfig)?;
                    let initial_read = packet_protection::PacketProtection::aes_128(
                        &qkdf::PacketKeys::aes_128(&secrets.server)
                            .map_err(|_| errors::ConnectFailure::InvalidConfig)?,
                    )
                    .map_err(|_| errors::ConnectFailure::InvalidConfig)?;
                    (
                        conn::handshake::Handshake::server(
                            initial_read,
                            initial_write,
                            crypto_journal_capacity,
                            outbound_layout,
                        ),
                        Tls::Client(conn::handshake::ClientTls::new(client)),
                        true,
                        initial_dcid,
                        None,
                        true,
                    )
                }
                Side::Server { peer_cid, shard } => {
                    user_tp.stateless_reset_token = stateless_reset_secret
                        .map(|s| secrets::StatelessResetSecret(s).token_for(&local_cid));
                    let tp_bytes = local_tp_bytes(
                        false,
                        &local_cid,
                        &original_dcid,
                        retry_scid.as_ref(),
                        user_tp,
                    )?;
                    let cfg = shin::server::config::Connection {
                        transport_params: tp_bytes,
                    };
                    let clock = clock::WallClock::now_millis as conn::handshake::Clock;
                    let server = shard
                        .new_quic(cfg, clock)
                        .map_err(|_| errors::ConnectFailure::Tls)?;
                    let outbound_layout = server
                        .outbound_layout()
                        .map_err(|_| errors::ConnectFailure::Tls)?;
                    let initial_write = packet_protection::PacketProtection::aes_128(
                        &qkdf::PacketKeys::aes_128(&secrets.server)
                            .map_err(|_| errors::ConnectFailure::InvalidConfig)?,
                    )
                    .map_err(|_| errors::ConnectFailure::InvalidConfig)?;
                    let initial_read = packet_protection::PacketProtection::aes_128(
                        &qkdf::PacketKeys::aes_128(&secrets.client)
                            .map_err(|_| errors::ConnectFailure::InvalidConfig)?,
                    )
                    .map_err(|_| errors::ConnectFailure::InvalidConfig)?;
                    (
                        conn::handshake::Handshake::server(
                            initial_read,
                            initial_write,
                            crypto_journal_capacity,
                            outbound_layout,
                        ),
                        Tls::Server(Box::new(server)),
                        false,
                        peer_cid,
                        Some(peer_cid),
                        false,
                    )
                }
                Side::ServerPooled { peer_cid, pool } => {
                    user_tp.stateless_reset_token = stateless_reset_secret
                        .map(|secret| secrets::StatelessResetSecret(secret).token_for(&local_cid));
                    let mut reservation = pool.reserve().ok_or(errors::ConnectFailure::Capacity)?;
                    user_tp
                        .encode_connection_retained(
                            false,
                            &local_cid,
                            &original_dcid,
                            retry_scid.as_deref(),
                            &mut reservation.transport_params(),
                        )
                        .map_err(|_| errors::ConnectFailure::InvalidConfig)?;
                    let server =
                        reservation.connect(clock::WallClock::now_millis as conn::handshake::Clock);
                    let outbound_layout = server
                        .outbound_layout()
                        .map_err(|_| errors::ConnectFailure::Tls)?;
                    let initial_write = packet_protection::PacketProtection::aes_128(
                        &qkdf::PacketKeys::aes_128(&secrets.server)
                            .map_err(|_| errors::ConnectFailure::InvalidConfig)?,
                    )
                    .map_err(|_| errors::ConnectFailure::InvalidConfig)?;
                    let initial_read = packet_protection::PacketProtection::aes_128(
                        &qkdf::PacketKeys::aes_128(&secrets.client)
                            .map_err(|_| errors::ConnectFailure::InvalidConfig)?,
                    )
                    .map_err(|_| errors::ConnectFailure::InvalidConfig)?;
                    (
                        conn::handshake::Handshake::server(
                            initial_read,
                            initial_write,
                            crypto_journal_capacity,
                            outbound_layout,
                        ),
                        Tls::ServerPooled(server),
                        false,
                        peer_cid,
                        Some(peer_cid),
                        false,
                    )
                }
            };

        let path = conn::path::Path::new(
            local_cid,
            initial_dcid,
            peer_cid,
            peer_first_scid,
            cid_prefix,
            stateless_reset_secret,
            local_active_connection_id_limit,
        );
        let egress = conn::egress::Egress::new(conn::egress::Setup {
            packet_journal_capacity,
            control_journal_capacity,
            stream_journal_capacity,
            max_pmtu,
            datagram_congestion_control,
            pending_datagrams_capacity,
            peer_address_validated,
        });
        let streams = conn::streams::Streams::new(conn::streams::Setup {
            is_client,
            event_capacity: stream_events_capacity,
            local_capacity: [local_bidi_stream_capacity, local_uni_stream_capacity],
            initial_max_streams: [
                local_initial_max_streams_bidi,
                local_initial_max_streams_uni,
            ],
            local_max_data,
            local_initial_stream_data: [
                local_initial_max_stream_data_bidi_local,
                local_initial_max_stream_data_bidi_remote,
                local_initial_max_stream_data_uni,
            ],
            stream_journal_capacity,
            receive_segment_capacity,
        });

        let mut conn = conn::session::Connection {
            egress,
            control: conn::control::Pending::new(control_journal_capacity),
            handshake,
            path,
            streams,
            receive: conn::session::ReceiveState {
                packet_numbers: Default::default(),
                crypto: array::from_fn(|_| conn::reassembly::Crypto::default()),
                datagrams: collections::VecDeque::new(),
                datagram_capacity: incoming_datagrams_capacity,
            },
            scratch: conn::session::Scratch {
                frames: Vec::with_capacity(new_reno::MAX_DATAGRAM_SIZE as usize),
                header: Vec::with_capacity(128),
            },
            peer: conn::session::PeerState {
                is_client,
                transport_params: None,
                local_max_idle_timeout: local_idle,
            },
        };
        if let Some(tp) = resumption_peer_tp {
            conn.streams
                .transmit
                .peer_data_credit
                .initialize(tp.initial_max_data);
            conn.streams.local_initiated.peer_max =
                [tp.initial_max_streams_bidi, tp.initial_max_streams_uni];
            conn.peer.transport_params = Some(tp);
        }
        Ok(match tls {
            Tls::Server(tls) => Built::Server {
                connection: conn,
                tls,
            },
            Tls::Client(mut tls) => {
                let outcome = tls
                    .start(&mut conn.handshake)
                    .map_err(|_| errors::ConnectFailure::Tls)?;
                outcome.apply(&mut conn);
                Built::ClientPooled {
                    connection: conn,
                    tls,
                }
            }
            Tls::ServerPooled(tls) => Built::ServerPooled {
                connection: conn,
                tls,
            },
            Tls::None => Built::Client(conn),
        })
    }
}
