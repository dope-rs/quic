use crate::stream;
use crate::{conn, errors, new_reno};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CongestionControl {
    #[default]
    Standard,
    Uncongested,
}

/// Exclusive access to a connection's unreliable-datagram queues.
pub struct Datagrams<'conn, const DOMAIN: u8, B: stream::ReceiveBuffer = Vec<u8>> {
    connection: &'conn mut conn::session::Connection<DOMAIN, B>,
}

impl<'conn, const DOMAIN: u8, B: stream::ReceiveBuffer> Datagrams<'conn, DOMAIN, B> {
    pub(in crate::conn) fn new(
        connection: &'conn mut conn::session::Connection<DOMAIN, B>,
    ) -> Self {
        Self { connection }
    }

    pub fn try_send(&mut self, data: Vec<u8>) -> Result<(), errors::SendFailure<Vec<u8>>> {
        if self.connection.egress.lifecycle.state == conn::State::Closed {
            return Err(errors::SendFailure::Closed(data));
        }
        let Some(max) = self.max_payload() else {
            return Err(errors::SendFailure::Unsupported(data));
        };
        if data.len() > max {
            return Err(errors::SendFailure::TooLarge(data));
        }
        if self.connection.egress.datagrams.pending_datagrams.len()
            >= self.connection.egress.datagrams.pending_datagrams_capacity
        {
            return Err(errors::SendFailure::Full(data));
        }
        self.connection
            .egress
            .datagrams
            .pending_datagrams
            .push_back(data);
        Ok(())
    }

    pub fn max_payload(&self) -> Option<usize> {
        let peer = self
            .connection
            .peer
            .transport_params
            .as_ref()
            .and_then(|parameters| parameters.max_datagram_frame_size)?;
        if peer == 0 {
            return None;
        }
        let by_peer = (peer as usize).saturating_sub(1);
        let overhead =
            1 + self.connection.path.peer_cid().len() + usize::from(conn::PN_LEN) + conn::TAG_LEN;
        let by_pmtu = (new_reno::MAX_DATAGRAM_SIZE as usize).saturating_sub(overhead);
        Some(by_peer.min(by_pmtu.saturating_sub(1)))
    }

    pub fn recv(&mut self) -> Option<B> {
        self.connection.receive.datagrams.pop_front()
    }

    pub fn recv_owned(&mut self) -> Option<Vec<u8>> {
        self.recv().map(stream::ReceiveBuffer::into_vec)
    }

    pub(crate) fn has_received(&self) -> bool {
        !self.connection.receive.datagrams.is_empty()
    }
}
