use std::collections::VecDeque;

use shin::client::{FramedClient, FramedConnection, QuicPostHandshake};
use shin::connection::{
    DriveError, Event, EventContext, EventSink, LendingEventSink, OutboundFlight, OutboundLayout,
};
use shin::server::QuicConnection;
use shin::server::config::{ClientCertVerifier, EarlyDataGuard};
use shin::wire::record::CipherSuite;

use crate::packet_protection::PacketProtection;
use crate::qkdf::PacketKeys;
use crate::{stream::ReceiveBuffer, transport_params};

use super::{Epoch, Error, State, crypto_tx, egress, path, session, streams};

const MAX_SESSION_TICKETS: usize = 8;
const MAX_SESSION_TICKET_BYTES: usize = 256 * 1024;

pub(crate) type Clock = fn() -> u64;

pub(super) struct Handshake<const DOMAIN: u8> {
    client: Option<Box<FramedClient<Clock>>>,
    read: [Option<PacketProtection>; 3],
    write: [Option<PacketProtection>; 3],
    zero_rtt_read: Option<PacketProtection>,
    zero_rtt_write: Option<PacketProtection>,
    crypto: crypto_tx::Tx,
    peer_transport_params: Option<transport_params::Params>,
    received_tickets: VecDeque<session::Ticket>,
    received_ticket_bytes: usize,
}

pub(super) struct Outcome {
    pub(super) done: bool,
    pub(super) reject_early_data: bool,
}

pub(super) trait Transition {
    fn reject_early_data(&mut self);
    fn establish(&mut self) -> Result<(), Error>;
    fn close(&mut self);
}

pub(super) fn apply_outcome(outcome: Outcome, transition: &mut impl Transition) {
    if outcome.reject_early_data {
        transition.reject_early_data();
    }
    if outcome.done && transition.establish().is_err() {
        transition.close();
    }
}

/// The exact connection fields consumed by a successful handshake transition.
/// Every value remains in its natural owner and every temporary borrow ends at
/// completion of this transition.
pub(super) struct Establishment<'a, const DOMAIN: u8, B: ReceiveBuffer> {
    pub(super) egress: &'a mut egress::Egress,
    pub(super) handshake: &'a mut Handshake<DOMAIN>,
    pub(super) path: &'a mut path::Path,
    pub(super) streams: &'a mut streams::State<B>,
    pub(super) peer_transport_params: &'a mut Option<transport_params::Params>,
    pub(super) is_client: bool,
}

impl<const DOMAIN: u8, B: ReceiveBuffer> Establishment<'_, DOMAIN, B> {
    pub(super) fn complete(self) -> Result<(), Error> {
        let peer_tp = self
            .handshake
            .take_peer_transport_params()
            .ok_or(Error::TransportParameterMismatch)?;

        let expected_iscid = self
            .path
            .peer_first_scid
            .as_ref()
            .ok_or(Error::TransportParameterMismatch)?;
        let peer_iscid = peer_tp
            .initial_source_connection_id
            .as_ref()
            .ok_or(Error::TransportParameterMismatch)?;
        if peer_iscid.as_slice() != expected_iscid.as_slice() {
            return Err(Error::TransportParameterMismatch);
        }

        if self.is_client {
            let peer_odcid = peer_tp
                .original_destination_connection_id
                .as_ref()
                .ok_or(Error::TransportParameterMismatch)?;
            if peer_odcid.as_slice() != self.path.original_dcid.as_slice() {
                return Err(Error::TransportParameterMismatch);
            }
        } else if peer_tp.original_destination_connection_id.is_some()
            || peer_tp.retry_source_connection_id.is_some()
        {
            return Err(Error::TransportParameterMismatch);
        }

        if self.is_client
            && let Some(token) = peer_tp.stateless_reset_token
        {
            self.path.set_initial_peer_reset_token(token);
        }
        self.streams
            .transmit
            .peer_data_credit
            .initialize(peer_tp.initial_max_data);
        self.streams.local_initiated.peer_max = [
            peer_tp.initial_max_streams_bidi,
            peer_tp.initial_max_streams_uni,
        ];
        let local_cids = self
            .path
            .issue_local_cids(peer_tp.active_connection_id_limit);
        *self.peer_transport_params = Some(peer_tp);
        self.egress.state = State::Established;
        self.egress
            .derived_controls
            .arm_established(!self.is_client, local_cids);
        Ok(())
    }
}

pub(super) trait Reader<const DOMAIN: u8> {
    fn read(
        &mut self,
        handshake: &mut Handshake<DOMAIN>,
        epoch: shin::connection::Epoch,
        data: &[u8],
        is_client: bool,
    ) -> Result<Outcome, Error>;
}

pub(super) struct ClientReader;

pub(crate) struct ClientTls<'pool> {
    state: Option<ClientTlsState<'pool>>,
}

enum ClientTlsState<'pool> {
    Handshaking(FramedConnection<'pool, Clock>),
    PostHandshake(QuicPostHandshake<'pool, Clock>),
}

impl<'pool> ClientTls<'pool> {
    pub(super) fn new(connection: FramedConnection<'pool, Clock>) -> Self {
        Self {
            state: Some(ClientTlsState::Handshaking(connection)),
        }
    }

    pub(super) fn start<const DOMAIN: u8>(
        &mut self,
        handshake: &mut Handshake<DOMAIN>,
    ) -> Result<Outcome, Error> {
        let Some(ClientTlsState::Handshaking(connection)) = self.state.as_mut() else {
            return Err(Error::Tls);
        };
        handshake.drive(true, |_, events| connection.start_into(events))
    }

    fn read<const DOMAIN: u8>(
        &mut self,
        handshake: &mut Handshake<DOMAIN>,
        epoch: shin::connection::Epoch,
        data: &[u8],
        is_client: bool,
    ) -> Result<Outcome, Error> {
        let outcome = match self.state.as_mut().ok_or(Error::Tls)? {
            ClientTlsState::Handshaking(connection) => handshake
                .drive(is_client, |_, events| {
                    connection.read_framed_into(epoch, data, events)
                })?,
            ClientTlsState::PostHandshake(connection) => handshake
                .drive(is_client, |_, events| {
                    connection.read_framed_into(epoch, data, events)
                })?,
        };
        if outcome.done && matches!(self.state, Some(ClientTlsState::Handshaking(_))) {
            let Some(ClientTlsState::Handshaking(connection)) = self.state.take() else {
                return Err(Error::Tls);
            };
            let post = connection
                .into_quic_post_handshake()
                .map_err(|_| Error::Tls)?;
            self.state = Some(ClientTlsState::PostHandshake(post));
        }
        Ok(outcome)
    }
}

pub(super) struct PooledClientReader<'a, 'pool> {
    tls: &'a mut ClientTls<'pool>,
}

impl<'a, 'pool> PooledClientReader<'a, 'pool> {
    pub(super) fn new(tls: &'a mut ClientTls<'pool>) -> Self {
        Self { tls }
    }
}

impl<const DOMAIN: u8> Reader<DOMAIN> for PooledClientReader<'_, '_> {
    fn read(
        &mut self,
        handshake: &mut Handshake<DOMAIN>,
        epoch: shin::connection::Epoch,
        data: &[u8],
        is_client: bool,
    ) -> Result<Outcome, Error> {
        self.tls.read(handshake, epoch, data, is_client)
    }
}

impl<const DOMAIN: u8> Reader<DOMAIN> for ClientReader {
    fn read(
        &mut self,
        handshake: &mut Handshake<DOMAIN>,
        epoch: shin::connection::Epoch,
        data: &[u8],
        is_client: bool,
    ) -> Result<Outcome, Error> {
        handshake.read_client(epoch, data, is_client)
    }
}

pub(super) struct ServerReader<'a, G, V, const DOMAIN: u8>
where
    G: EarlyDataGuard,
    V: ClientCertVerifier,
{
    server: &'a mut QuicConnection<Clock, DOMAIN, G, V>,
}

pub(super) struct PooledServerReader<'a, 'pool, G, V, const DOMAIN: u8>
where
    G: EarlyDataGuard,
    V: ClientCertVerifier,
{
    server: &'a mut shin::server::QuicPooledConnection<'pool, Clock, DOMAIN, V, G>,
}

impl<'a, 'pool, G, V, const DOMAIN: u8> PooledServerReader<'a, 'pool, G, V, DOMAIN>
where
    G: EarlyDataGuard,
    V: ClientCertVerifier,
{
    pub(super) fn new(
        server: &'a mut shin::server::QuicPooledConnection<'pool, Clock, DOMAIN, V, G>,
    ) -> Self {
        Self { server }
    }
}

impl<G, V, const DOMAIN: u8> Reader<DOMAIN> for PooledServerReader<'_, '_, G, V, DOMAIN>
where
    G: EarlyDataGuard,
    V: ClientCertVerifier,
{
    fn read(
        &mut self,
        handshake: &mut Handshake<DOMAIN>,
        epoch: shin::connection::Epoch,
        data: &[u8],
        is_client: bool,
    ) -> Result<Outcome, Error> {
        handshake.drive(is_client, |client, events| match client {
            Some(_) => Err(shin::connection::Error::BadConfig.into()),
            None => self.server.read_framed_into(epoch, data, events),
        })
    }
}

pub(super) struct FinishedReader;

impl<const DOMAIN: u8> Reader<DOMAIN> for FinishedReader {
    fn read(
        &mut self,
        _handshake: &mut Handshake<DOMAIN>,
        _epoch: shin::connection::Epoch,
        _data: &[u8],
        _is_client: bool,
    ) -> Result<Outcome, Error> {
        Err(Error::Tls)
    }
}

impl<'a, G, V, const DOMAIN: u8> ServerReader<'a, G, V, DOMAIN>
where
    G: EarlyDataGuard,
    V: ClientCertVerifier,
{
    pub(super) fn new(server: &'a mut QuicConnection<Clock, DOMAIN, G, V>) -> Self {
        Self { server }
    }
}

impl<G, V, const DOMAIN: u8> Reader<DOMAIN> for ServerReader<'_, G, V, DOMAIN>
where
    G: EarlyDataGuard,
    V: ClientCertVerifier,
{
    fn read(
        &mut self,
        handshake: &mut Handshake<DOMAIN>,
        epoch: shin::connection::Epoch,
        data: &[u8],
        is_client: bool,
    ) -> Result<Outcome, Error> {
        handshake.read_server(epoch, data, self.server, is_client)
    }
}

impl<const DOMAIN: u8> Handshake<DOMAIN> {
    pub(super) fn client(
        client: FramedClient<Clock>,
        initial_read: PacketProtection,
        initial_write: PacketProtection,
        crypto_capacity: usize,
        outbound_layout: OutboundLayout,
    ) -> Self {
        Self::new(
            Some(Box::new(client)),
            initial_read,
            initial_write,
            crypto_capacity,
            outbound_layout,
        )
    }

    pub(super) fn server(
        initial_read: PacketProtection,
        initial_write: PacketProtection,
        crypto_capacity: usize,
        outbound_layout: OutboundLayout,
    ) -> Self {
        Self::new(
            None,
            initial_read,
            initial_write,
            crypto_capacity,
            outbound_layout,
        )
    }

    fn new(
        client: Option<Box<FramedClient<Clock>>>,
        initial_read: PacketProtection,
        initial_write: PacketProtection,
        crypto_capacity: usize,
        outbound_layout: OutboundLayout,
    ) -> Self {
        Self {
            client,
            read: [Some(initial_read), None, None],
            write: [Some(initial_write), None, None],
            zero_rtt_read: None,
            zero_rtt_write: None,
            crypto: crypto_tx::Tx::new(crypto_capacity, outbound_layout),
            peer_transport_params: None,
            received_tickets: VecDeque::new(),
            received_ticket_bytes: 0,
        }
    }

    pub(super) fn start_client(&mut self) -> Result<Outcome, Error> {
        self.drive(true, |client, events| match client {
            Some(client) => client.start_into(events),
            None => Err(shin::connection::Error::BadConfig.into()),
        })
    }

    fn read_client(
        &mut self,
        epoch: shin::connection::Epoch,
        data: &[u8],
        is_client: bool,
    ) -> Result<Outcome, Error> {
        self.drive(is_client, |client, events| match client {
            Some(client) => client.read_framed_into(epoch, data, events),
            None => Err(shin::connection::Error::BadConfig.into()),
        })
    }

    fn read_server<G, V>(
        &mut self,
        epoch: shin::connection::Epoch,
        data: &[u8],
        server: &mut QuicConnection<Clock, DOMAIN, G, V>,
        is_client: bool,
    ) -> Result<Outcome, Error>
    where
        G: EarlyDataGuard,
        V: ClientCertVerifier,
    {
        self.drive(is_client, |client, events| match client {
            Some(_) => Err(shin::connection::Error::BadConfig.into()),
            None => server.read_framed_into(epoch, data, events),
        })
    }

    fn drive(
        &mut self,
        is_client: bool,
        run: impl FnOnce(
            &mut Option<Box<FramedClient<Clock>>>,
            &mut Events<'_>,
        ) -> Result<(), DriveError<Error>>,
    ) -> Result<Outcome, Error> {
        let Self {
            client,
            read,
            write,
            zero_rtt_read,
            zero_rtt_write,
            crypto,
            peer_transport_params,
            received_tickets,
            received_ticket_bytes,
        } = self;
        let mut events = Events {
            read,
            write,
            zero_rtt_read,
            zero_rtt_write,
            crypto,
            peer_transport_params,
            received_tickets,
            received_ticket_bytes,
            is_client,
            done: false,
            reject_early_data: false,
        };
        match run(client, &mut events) {
            Ok(()) => Ok(Outcome {
                done: events.done,
                reject_early_data: events.reject_early_data,
            }),
            Err(DriveError::Protocol(_)) => Err(Error::Tls),
            Err(DriveError::Sink(error)) => Err(error),
        }
    }

    pub(super) fn read_key(&self, epoch: Epoch) -> Option<&PacketProtection> {
        self.read[epoch as usize].as_ref()
    }

    pub(super) fn write_key(&self, epoch: Epoch) -> Option<&PacketProtection> {
        self.write[epoch as usize].as_ref()
    }

    pub(super) fn zero_rtt_read_key(&self) -> Option<&PacketProtection> {
        self.zero_rtt_read.as_ref()
    }

    pub(super) fn zero_rtt_write_key(&self) -> Option<&PacketProtection> {
        self.zero_rtt_write.as_ref()
    }

    pub(super) fn replace_initial_keys(&mut self, read: PacketProtection, write: PacketProtection) {
        self.read[Epoch::Initial as usize] = Some(read);
        self.write[Epoch::Initial as usize] = Some(write);
    }

    pub(super) fn discard(&mut self, epoch: Epoch) {
        self.read[epoch as usize] = None;
        self.write[epoch as usize] = None;
        self.crypto.discard(epoch);
    }

    pub(super) fn crypto(&self) -> &crypto_tx::Tx {
        &self.crypto
    }

    pub(super) fn crypto_mut(&mut self) -> &mut crypto_tx::Tx {
        &mut self.crypto
    }

    pub(super) fn retry_initial_crypto(&mut self) {
        self.crypto.retry_initial();
    }

    fn take_peer_transport_params(&mut self) -> Option<transport_params::Params> {
        self.peer_transport_params.take()
    }

    pub(super) fn take_session_tickets(&mut self) -> Vec<session::Ticket> {
        self.received_ticket_bytes = 0;
        self.received_tickets.drain(..).collect()
    }
}

struct Events<'a> {
    read: &'a mut [Option<PacketProtection>; 3],
    write: &'a mut [Option<PacketProtection>; 3],
    zero_rtt_read: &'a mut Option<PacketProtection>,
    zero_rtt_write: &'a mut Option<PacketProtection>,
    crypto: &'a mut crypto_tx::Tx,
    peer_transport_params: &'a mut Option<transport_params::Params>,
    received_tickets: &'a mut VecDeque<session::Ticket>,
    received_ticket_bytes: &'a mut usize,
    is_client: bool,
    done: bool,
    reject_early_data: bool,
}

impl EventSink for Events<'_> {
    type Error = Error;

    fn begin_send(
        &mut self,
        epoch: shin::connection::Epoch,
        _maximum: usize,
        context: EventContext,
    ) -> Result<Option<OutboundFlight<'_>>, Self::Error> {
        LendingEventSink::lend_send(self, epoch, context).map(Some)
    }

    fn event(&mut self, event: Event<'_>, context: EventContext) -> Result<(), Self::Error> {
        match event {
            Event::Send { epoch, data } => match epoch {
                shin::connection::Epoch::Plaintext => self.crypto.append(Epoch::Initial, data)?,
                shin::connection::Epoch::Handshake => self.crypto.append(Epoch::Handshake, data)?,
                shin::connection::Epoch::Application => {
                    self.crypto.append(Epoch::Application, data)?
                }
                shin::connection::Epoch::EarlyData => {}
            },
            Event::KeysReady {
                epoch,
                read_secret,
                write_secret,
            } => {
                if context.cipher_suite() != Some(CipherSuite::Aes128GcmSha256) {
                    return Err(Error::Tls);
                }
                let read_keys =
                    PacketKeys::aes_128(read_secret.as_slice()).map_err(|_| Error::Tls)?;
                let write_keys =
                    PacketKeys::aes_128(write_secret.as_slice()).map_err(|_| Error::Tls)?;
                let read = PacketProtection::aes_128(&read_keys).map_err(|_| Error::Tls)?;
                let write = PacketProtection::aes_128(&write_keys).map_err(|_| Error::Tls)?;
                let index = match epoch {
                    shin::connection::Epoch::Handshake => Epoch::Handshake as usize,
                    shin::connection::Epoch::Application => Epoch::Application as usize,
                    shin::connection::Epoch::Plaintext | shin::connection::Epoch::EarlyData => {
                        return Err(Error::Tls);
                    }
                };
                self.read[index] = Some(read);
                self.write[index] = Some(write);
            }
            Event::PeerExtension { ty, data } => {
                if ty != shin::wire::extension::Type::QUIC_TRANSPORT_PARAMETERS.0
                    || self.peer_transport_params.is_some()
                {
                    return Err(Error::TransportParameterDecode);
                }
                *self.peer_transport_params = Some(transport_params::Params::decode(data)?);
            }
            Event::Done => self.done = true,
            Event::KeyUpdate { .. } => return Err(Error::Tls),
            Event::ZeroRttKeysReady { secret, .. } => {
                let keys = PacketKeys::aes_128(secret.as_slice()).map_err(|_| Error::Tls)?;
                let protection = PacketProtection::aes_128(&keys).map_err(|_| Error::Tls)?;
                if self.is_client {
                    *self.zero_rtt_write = Some(protection);
                } else {
                    *self.zero_rtt_read = Some(protection);
                }
            }
            Event::EarlyDataAccepted => {}
            Event::EarlyDataRejected => {
                *self.zero_rtt_write = None;
                self.reject_early_data = true;
            }
            Event::NewSessionTicket(ticket) => {
                let alpn = ticket.alpn().map(<[u8]>::to_vec);
                let ticket_bytes = ticket
                    .ticket()
                    .len()
                    .saturating_add(alpn.as_ref().map_or(0, Vec::len));
                if ticket_bytes > MAX_SESSION_TICKET_BYTES {
                    return Ok(());
                }
                while self.received_tickets.len() >= MAX_SESSION_TICKETS
                    || self.received_ticket_bytes.saturating_add(ticket_bytes)
                        > MAX_SESSION_TICKET_BYTES
                {
                    let Some(expired) = self.received_tickets.pop_front() else {
                        break;
                    };
                    *self.received_ticket_bytes = self.received_ticket_bytes.saturating_sub(
                        expired.ticket.len() + expired.alpn.as_ref().map_or(0, Vec::len),
                    );
                }
                let psk = ticket.try_psk().map_err(|_| Error::Tls)?;
                self.received_tickets.push_back(session::Ticket {
                    ticket_lifetime: ticket.ticket_lifetime_secs(),
                    ticket_age_add: ticket.ticket_age_add(),
                    received_at_ms: ticket.received_at_ms(),
                    ticket: ticket.ticket().to_vec(),
                    psk,
                    max_early_data: ticket.max_early_data(),
                    cipher_suite: ticket.cipher_suite(),
                    alpn,
                });
                *self.received_ticket_bytes += ticket_bytes;
            }
        }
        Ok(())
    }
}

impl LendingEventSink for Events<'_> {
    fn lend_send(
        &mut self,
        epoch: shin::connection::Epoch,
        _context: EventContext,
    ) -> Result<OutboundFlight<'_>, Self::Error> {
        let epoch = match epoch {
            shin::connection::Epoch::Plaintext => Epoch::Initial,
            shin::connection::Epoch::Handshake => Epoch::Handshake,
            shin::connection::Epoch::Application => Epoch::Application,
            shin::connection::Epoch::EarlyData => return Err(Error::Tls),
        };
        self.crypto.begin(epoch)
    }
}
