use crate::stream::ReceiveBuffer;
use crate::{conn, stream};
use conn::streams::events::Events as _;
use conn::streams::receive::Receive as _;
use conn::streams::transmit::Transmit as _;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    NotEstablished,
    PeerLimit,
    Capacity,
    IdOverflow,
    InvalidStream,
    ValueOutOfRange,
}

impl_error!(Error {
    Self::NotEstablished => "connection is not established",
    Self::PeerLimit => "peer stream limit reached",
    Self::Capacity => "local active stream capacity reached",
    Self::IdOverflow => "stream ID space exhausted",
    Self::InvalidStream => "invalid stream operation",
    Self::ValueOutOfRange => "stream value is out of range",
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Bytes, FIN, or both are ready. Drain the receive side, then inspect
    /// [`View::recv_eof`]. Only one readable notice is pending per stream.
    Readable {
        stream_id: u64,
    },
    Reset {
        stream_id: u64,
        error_code: u64,
    },
    Stopped {
        stream_id: u64,
        error_code: u64,
    },
}

/// Immutable stream state for the lifetime of the connection borrow.
pub struct View<'conn, const DOMAIN: u8, B: ReceiveBuffer = Vec<u8>> {
    connection: &'conn conn::session::Connection<DOMAIN, B>,
}

impl<'conn, const DOMAIN: u8, B: ReceiveBuffer> View<'conn, DOMAIN, B> {
    pub(in crate::conn) fn new(connection: &'conn conn::session::Connection<DOMAIN, B>) -> Self {
        Self { connection }
    }

    pub fn recv_eof(&self, stream_id: u64) -> bool {
        self.connection
            .streams
            .recv_eof(stream_id, self.connection.is_client)
    }

    pub fn recv_fin_received(&self, stream_id: u64) -> bool {
        self.connection
            .streams
            .recv_fin_received(stream_id, self.connection.is_client)
    }

    pub fn stopped(&self, stream_id: u64) -> Option<u64> {
        self.connection.streams.send_stopped(stream_id)
    }

    pub fn has_events(&self) -> bool {
        self.connection.streams.has_events()
    }
}

/// Exclusive access to a connection's stream event queue.
pub struct Events<'conn, const DOMAIN: u8, B: ReceiveBuffer = Vec<u8>> {
    connection: &'conn mut conn::session::Connection<DOMAIN, B>,
}

impl<'conn, const DOMAIN: u8, B: ReceiveBuffer> Events<'conn, DOMAIN, B> {
    pub(in crate::conn) fn new(
        connection: &'conn mut conn::session::Connection<DOMAIN, B>,
    ) -> Self {
        Self { connection }
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.connection.streams.poll_event()
    }
}

/// Exclusive access to a connection's stream state for the lifetime of the borrow.
pub struct Streams<'conn, const DOMAIN: u8, B: ReceiveBuffer = Vec<u8>> {
    connection: &'conn mut conn::session::Connection<DOMAIN, B>,
}

impl<'conn, const DOMAIN: u8, B: ReceiveBuffer> Streams<'conn, DOMAIN, B> {
    pub(in crate::conn) fn new(
        connection: &'conn mut conn::session::Connection<DOMAIN, B>,
    ) -> Self {
        Self { connection }
    }

    fn operations_available(&self) -> bool {
        self.connection.egress.state == conn::State::Established
            || self.connection.is_client
                && self.connection.egress.state == conn::State::Handshaking
                && self.connection.handshake.zero_rtt_write_key().is_some()
                && self.connection.peer_transport_params.is_some()
    }

    pub fn recv(&mut self, stream_id: u64, destination: &mut Vec<u8>) -> usize {
        self.connection.streams.read(
            stream_id,
            destination,
            self.connection.is_client,
            &mut self.connection.control,
        )
    }

    /// Transfers contiguous receive storage and releases flow-control credit.
    /// Returns `None` when no new bytes are readable.
    pub fn recv_owned(&mut self, stream_id: u64) -> Option<Vec<u8>> {
        self.connection.streams.read_owned(
            stream_id,
            self.connection.is_client,
            &mut self.connection.control,
        )
    }

    /// Transfers one contiguous receive segment without copying.
    pub fn recv_buffer(&mut self, stream_id: u64) -> Option<B> {
        self.connection.streams.read_buffer(
            stream_id,
            self.connection.is_client,
            &mut self.connection.control,
        )
    }

    pub fn send(&mut self, stream_id: u64, data: &[u8]) -> Result<(), Error> {
        let available = self.operations_available();
        self.connection.streams.send_bytes(
            stream_id,
            data,
            self.connection.peer_transport_params.as_ref(),
            self.connection.is_client,
            available,
        )
    }

    pub fn send_buffer(&mut self, stream_id: u64, data: stream::SendBuffer) -> Result<(), Error> {
        let available = self.operations_available();
        self.connection.streams.send_buffer(
            stream_id,
            data,
            self.connection.peer_transport_params.as_ref(),
            self.connection.is_client,
            available,
        )
    }

    /// Appends a segmented write and its FIN with one stream lookup.
    pub fn send_parts(
        &mut self,
        stream_id: u64,
        first: stream::SendBuffer,
        second: Option<stream::SendBuffer>,
        fin: bool,
    ) -> Result<(), Error> {
        let available = self.operations_available();
        self.connection.streams.send_parts(
            stream_id,
            conn::streams::transmit::SendParts::new(first, second, fin),
            self.connection.peer_transport_params.as_ref(),
            self.connection.is_client,
            available,
        )
    }

    pub fn finish(&mut self, stream_id: u64) -> Result<(), Error> {
        let available = self.operations_available();
        self.connection.streams.send_fin(
            stream_id,
            self.connection.peer_transport_params.as_ref(),
            self.connection.is_client,
            available,
        )
    }

    pub fn reset(&mut self, stream_id: u64, error_code: u64) -> Result<(), Error> {
        let available = self.operations_available();
        self.connection.streams.reset(
            stream_id,
            error_code,
            self.connection.peer_transport_params.as_ref(),
            self.connection.is_client,
            available,
            &mut self.connection.control,
        )
    }

    pub fn stop(&mut self, stream_id: u64, error_code: u64) -> Result<(), Error> {
        let available = self.operations_available();
        self.connection.streams.stop_sending(
            stream_id,
            error_code,
            self.connection.is_client,
            available,
            &mut self.connection.control,
        )
    }

    pub fn open_bidi(&mut self) -> Result<u64, Error> {
        let available = self.operations_available();
        self.connection.streams.open_local(
            false,
            self.connection.peer_transport_params.as_ref(),
            self.connection.is_client,
            available,
        )
    }

    pub fn open_uni(&mut self) -> Result<u64, Error> {
        let available = self.operations_available();
        self.connection.streams.open_local(
            true,
            self.connection.peer_transport_params.as_ref(),
            self.connection.is_client,
            available,
        )
    }
}
