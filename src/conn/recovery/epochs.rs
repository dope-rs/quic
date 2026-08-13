use crate::{conn, pn_space, stream};

#[derive(Clone, Copy, Default)]
pub(in crate::conn) struct Discarded(u8);

impl Discarded {
    pub(in crate::conn) fn record(&mut self, epoch: conn::Epoch) {
        self.0 |= 1 << epoch as u8;
    }

    pub(in crate::conn) fn apply(self, received: &mut [pn_space::Receive; 3]) {
        for (index, receive) in received.iter_mut().enumerate() {
            if self.0 & (1 << index) != 0 {
                *receive = pn_space::Receive::default();
            }
        }
    }
}

pub(in crate::conn) struct Transition<'a, const DOMAIN: u8> {
    egress: &'a mut conn::egress::Egress,
    handshake: &'a mut conn::handshake::Handshake<DOMAIN>,
}

impl<'a, const DOMAIN: u8> Transition<'a, DOMAIN> {
    pub(in crate::conn) fn new(
        egress: &'a mut conn::egress::Egress,
        handshake: &'a mut conn::handshake::Handshake<DOMAIN>,
    ) -> Self {
        Self { egress, handshake }
    }

    pub(in crate::conn) fn discard_initial(&mut self) {
        self.discard_packets(conn::Epoch::Initial);
        self.handshake.discard(conn::Epoch::Initial);
        self.egress.recovery.spaces[conn::Epoch::Initial as usize] = crate::PnSpace::default();
    }

    pub(in crate::conn) fn retry_initial(&mut self) {
        self.discard_packets(conn::Epoch::Initial);
        self.handshake.retry_initial_crypto();
        self.egress.recovery.spaces[conn::Epoch::Initial as usize] = crate::PnSpace::default();
    }

    pub(in crate::conn) fn discard_handshake(&mut self) {
        self.discard_packets(conn::Epoch::Handshake);
        self.handshake.discard(conn::Epoch::Handshake);
        self.egress.recovery.spaces[conn::Epoch::Handshake as usize] = crate::PnSpace::default();
    }

    fn discard_packets(&mut self, epoch: conn::Epoch) {
        let leaked = self.egress.recovery.packet_journals.in_flight_bytes(epoch);
        self.egress.congestion.cc.discard(leaked);
        self.egress
            .recovery
            .packet_journals
            .drain_where(|journal| journal.epoch == epoch, |_, _, _| {});
    }
}

pub(in crate::conn) struct Epochs<'a, const DOMAIN: u8, B: stream::ReceiveBuffer> {
    connection: &'a mut conn::session::Connection<DOMAIN, B>,
}

impl<'a, const DOMAIN: u8, B: stream::ReceiveBuffer> Epochs<'a, DOMAIN, B> {
    pub(in crate::conn) fn new(connection: &'a mut conn::session::Connection<DOMAIN, B>) -> Self {
        Self { connection }
    }

    pub(in crate::conn) fn discard_initial(&mut self) {
        Transition::new(&mut self.connection.egress, &mut self.connection.handshake)
            .discard_initial();
        self.connection.receive.packet_numbers[conn::Epoch::Initial as usize] =
            pn_space::Receive::default();
        self.connection.receive.crypto[conn::Epoch::Initial as usize].discard();
    }

    pub(in crate::conn) fn retry_initial(&mut self) {
        Transition::new(&mut self.connection.egress, &mut self.connection.handshake)
            .retry_initial();
        self.connection.receive.packet_numbers[conn::Epoch::Initial as usize] =
            pn_space::Receive::default();
        self.connection.receive.crypto[conn::Epoch::Initial as usize].discard();
    }

    pub(in crate::conn) fn discard_handshake(&mut self) {
        Transition::new(&mut self.connection.egress, &mut self.connection.handshake)
            .discard_handshake();
        self.connection.receive.packet_numbers[conn::Epoch::Handshake as usize] =
            pn_space::Receive::default();
        self.connection.receive.crypto[conn::Epoch::Handshake as usize].discard();
    }
}
