use o3::buffer::{self, resident};

use crate::proto::datagram;
use crate::stream;
use crate::{conn, errors};

/// Exclusive access to a connection's unreliable-datagram queues.
#[repr(transparent)]
pub struct Datagrams<
    'conn,
    const DOMAIN: u8,
    B: stream::Recv = Vec<u8>,
    const RECONCILE: bool = false,
    D: buffer::raw::Segment = resident::Shared<'conn>,
> {
    connection: &'conn mut conn::Machine<DOMAIN, B, D>,
}

impl<'conn, const DOMAIN: u8, B: stream::Recv, const RECONCILE: bool, D: buffer::raw::Segment>
    Datagrams<'conn, DOMAIN, B, RECONCILE, D>
{
    pub(in crate::conn) fn new(conn: &'conn mut conn::Machine<DOMAIN, B, D>) -> Self {
        Self { connection: conn }
    }

    pub fn try_send(&mut self, data: Vec<u8>) -> Result<(), errors::SendFailure<Vec<u8>>> {
        if self.connection.is_closing() {
            return Err(errors::SendFailure::Closed(data));
        }
        let Some(max) = self.max_payload() else {
            return Err(errors::SendFailure::Unsupported(data));
        };
        if data.len() > max {
            return Err(errors::SendFailure::TooLarge(data));
        }
        self.connection.egress.datagrams.try_push(data)?;
        self.connection.record::<RECONCILE>(conn::Effects::TRANSMIT);
        Ok(())
    }

    pub fn max_payload(&self) -> Option<usize> {
        let peer = self
            .connection
            .peer
            .transport_params
            .as_ref()
            .and_then(|params| params.flow().datagram())?;
        if peer == 0 {
            return None;
        }
        let by_peer = usize::try_from(peer).ok()?.saturating_sub(1);
        let bytes = usize::try_from(self.connection.egress.cc.metrics().current_mtu()).ok()?;
        let by_pmtu = datagram::Arena::payload_max(bytes, self.connection.path.peer.id().len())?;
        Some(by_peer.min(by_pmtu))
    }

    pub fn recv(&mut self) -> Option<B> {
        let result = self.connection.receive.datagrams.pop_front();
        if result.is_some() {
            self.connection.record::<RECONCILE>(conn::Effects::NOTIFY);
        }
        result
    }
}
