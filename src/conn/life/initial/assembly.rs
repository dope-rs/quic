use o3::{alloc::VecExt as _, buffer};
use std::collections;

use crate::{
    conn, errors, proto, proto::recovery::numbers, proto::recovery::pmtud, runtime::routing, stream,
};
use conn::stream::Streams;
use conn::{life, output, wire};
use initial::seed;
use life::{initial, options};
use output::control;
use proto::param::Set;
use wire::crypto::chunks;
use wire::{
    path::{self, setup},
    tls,
};

pub(super) struct Assembly<R, const DOMAIN: u8> {
    pub(super) input: options::Options,
    pub(super) wire: tls::Handshake<DOMAIN>,
    pub(super) role: R,
}

pub(super) struct Client {
    pub(super) seed: seed::Seed<seed::Client>,
    pub(super) token: Option<Vec<u8>>,
    pub(super) shard: Option<routing::Shard>,
}

pub(super) struct Server {
    pub(super) seed: seed::Seed<seed::Server>,
}

struct Ready {
    base: seed::Base,
    tokens: setup::Tokens,
    shard: Option<routing::Shard>,
}

impl<const DOMAIN: u8> Assembly<Client, DOMAIN> {
    pub(super) fn try_finish<B, D>(
        self,
        peer: &mut Option<Set>,
    ) -> Result<conn::Connection<DOMAIN, B, D>, errors::Connect>
    where
        B: stream::Recv,
        D: buffer::raw::Segment,
    {
        let Self {
            input,
            wire,
            role: Client { seed, token, shard },
        } = self;
        let (base, seed::Client) = seed.into_parts();
        Assembly {
            input,
            wire,
            role: Ready {
                base,
                tokens: setup::Tokens::Client(token.unwrap_or_default()),
                shard,
            },
        }
        .try_ready(peer)
    }
}

impl<const DOMAIN: u8> Assembly<Server, DOMAIN> {
    pub(super) fn try_finish<B, D>(self) -> Result<conn::Connection<DOMAIN, B, D>, errors::Connect>
    where
        B: stream::Recv,
        D: buffer::raw::Segment,
    {
        let Self {
            input,
            wire,
            role: Server { seed },
        } = self;
        let (base, seed::Server { token }) = seed.into_parts();
        let mut peer = None;
        Assembly {
            input,
            wire,
            role: Ready {
                base,
                tokens: setup::Tokens::Server(token),
                shard: None,
            },
        }
        .try_ready(&mut peer)
    }
}

impl<const DOMAIN: u8> Assembly<Ready, DOMAIN> {
    fn try_ready<B, D>(
        self,
        peer: &mut Option<Set>,
    ) -> Result<conn::Connection<DOMAIN, B, D>, errors::Connect>
    where
        B: stream::Recv,
        D: buffer::raw::Segment,
    {
        let Self {
            input,
            wire,
            role:
                Ready {
                    base,
                    tokens,
                    shard,
                },
        } = self;
        let dcid = base.initial_dcid;
        let local = base.local_cid;
        let valid = base.peer_address_validated;
        let remote = base.peer_cid;
        let first = base.peer_first_scid;
        let options::Options {
            transport: cfg,
            datagrams: dgram,
            streams: opts,
            journals: logs,
            security: crypto,
        } = input;
        let tp = cfg.params();
        let timer = tp.timing();
        let flow = cfg.flow();
        let pkt = logs.packet();
        let ctrl = logs.control();
        let strm = logs.stream();
        let side = tokens.initiator();
        let route = path::State::new(setup::Setup {
            identities: setup::Identities {
                local_cid: local,
                original_dcid: dcid,
                peer_cid: remote,
                peer_first_scid: first,
            },
            tokens,
            peer_shard: shard,
            stateless_reset_secret: crypto.stateless_reset_secret,
            options: cfg.identity(),
        });
        let egress = output::Egress::new(output::Setup {
            packet_journal_capacity: pkt,
            control_journal_capacity: ctrl,
            stream_journal_capacity: strm,
            max_pmtu: cfg.max_pmtu(),
            pending_datagrams_capacity: dgram.pending(),
            peer_address_validated: valid,
        });
        let stream = Streams::try_new(side, strm, flow, opts).map_err(errors::Connect::Stream)?;
        let mut conn = conn::Connection(conn::Machine {
            egress,
            control: control::Pending::new(ctrl),
            handshake: wire,
            path: route,
            streams: stream,
            receive: conn::ReceiveState {
                packet_numbers: numbers::Spaces::new(timer.ack_ms(), timer.ack_exponent()),
                crypto: chunks::Spaces::new(),
                datagrams: collections::VecDeque::new(),
                datagram_capacity: dgram.incoming(),
                local_max_datagram_frame_size: flow.datagram(),
            },
            scratch: conn::Scratch {
                frames: Vec::try_new(pmtud::BASE_PMTU as usize)?,
                header: Vec::try_new(128)?,
            },
            peer: conn::PeerState {
                local: side,
                application_timeout: false,
                reconcile: conn::Effects::initial(),
                transport_params: None,
                local_max_idle_ms: timer.idle_ms(),
                application_deadline: None,
            },
        });
        if let Some(peer) = peer.take() {
            let saved = peer.flow();
            let core = conn.machine_mut();
            core.streams
                .transmit
                .peer
                .data_credit
                .raise(saved.initial_data(), &mut core.control);
            core.streams.local_initiated.peer_max = [saved.bidi_count(), saved.uni_count()];
            core.peer.transport_params = Some(peer);
        }
        Ok(conn)
    }
}
