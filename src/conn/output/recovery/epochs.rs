use crate::{
    conn::{self, output, wire::tls},
    proto::recovery::numbers,
    stream,
};
use o3::buffer;

#[derive(Clone, Copy, Default)]
pub(in crate::conn) enum Discarded {
    #[default]
    Empty,
    Handshake,
}

impl Discarded {
    pub(in crate::conn) fn confirm(&mut self) {
        *self = Self::Handshake;
    }

    pub(in crate::conn) fn apply(self, received: &mut numbers::Spaces) {
        if matches!(self, Self::Handshake) {
            received.discard(conn::Epoch::Initial);
            received.discard(conn::Epoch::Handshake);
        }
    }
}

pub(in crate::conn) struct Transition<'a, const DOMAIN: u8> {
    egress: &'a mut output::Egress,
    handshake: &'a mut tls::Handshake<DOMAIN>,
}

impl<'a, const DOMAIN: u8> Transition<'a, DOMAIN> {
    pub(in crate::conn) fn new(
        egress: &'a mut output::Egress,
        state: &'a mut tls::Handshake<DOMAIN>,
    ) -> Self {
        Self {
            egress,
            handshake: state,
        }
    }

    pub(in crate::conn) fn discard(&mut self, epoch: conn::Epoch) {
        self.drain(epoch);
        self.handshake.discard(epoch);
        *epoch.bind_mut(&mut self.egress.recovery.spaces) = numbers::PnSpace::default();
    }

    pub(in crate::conn) fn retry(&mut self) {
        self.drain(conn::Epoch::Initial);
        self.handshake.crypto.retry();
        *conn::Epoch::Initial.bind_mut(&mut self.egress.recovery.spaces) =
            numbers::PnSpace::default();
    }

    fn drain(&mut self, epoch: conn::Epoch) {
        *epoch.bind_mut(&mut self.egress.recovery.streaks) = Default::default();
        let recovery = &mut self.egress.recovery;
        if match epoch {
            conn::Epoch::Initial => self.handshake.keys.long.initial().is_some(),
            conn::Epoch::Handshake => self.handshake.keys.long.handshake().is_some(),
            conn::Epoch::Application => false,
        } {
            recovery.probe.count.reset();
        }
        if recovery.probe.epoch == Some(epoch) {
            recovery.probe.allowance.clear();
            recovery.probe.epoch = None;
        }
        recovery.packet_journals.space_mut(epoch).discard();
    }
}

pub(in crate::conn) struct Epochs<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> {
    connection: &'a mut conn::Machine<DOMAIN, B, D>,
}

impl<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> Epochs<'a, DOMAIN, B, D> {
    pub(in crate::conn) fn new(conn: &'a mut conn::Machine<DOMAIN, B, D>) -> Self {
        Self { connection: conn }
    }

    pub(in crate::conn) fn discard(&mut self, epoch: conn::Epoch) {
        Transition::new(&mut self.connection.egress, &mut self.connection.handshake).discard(epoch);
        self.connection.receive.packet_numbers.discard(epoch);
        self.connection.receive.crypto.discard(epoch);
    }

    pub(in crate::conn) fn retry(&mut self) {
        Transition::new(&mut self.connection.egress, &mut self.connection.handshake).retry();
        self.connection
            .receive
            .packet_numbers
            .discard(conn::Epoch::Initial);
        self.connection.receive.crypto.discard(conn::Epoch::Initial);
    }
}
