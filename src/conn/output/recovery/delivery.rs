use crate::conn::output::control::journal::records::Records;
use crate::conn::output::delivery;
use crate::conn::output::journals::stack;
use crate::stream::release;
use o3::buffer;
use std::time;

use crate::conn::output::journals::{controls, streams};
use crate::conn::output::{self, cc, control, journals, recovery::timer};
use crate::conn::stream::event::queue::Pending;
use crate::conn::stream::{State, state::receive};
use crate::conn::wire::tls;
use crate::{conn, stream};
use control::revision;

pub(super) struct Delivery<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, E> {
    pub(super) egress: &'a mut output::Egress,
    pub(super) control: &'a mut control::Pending,
    pub(super) handshake: &'a mut tls::Handshake<DOMAIN>,
    pub(super) streams: &'a mut State<B, D>,
    pub(super) stream_events: &'a mut Pending,
    pub(super) release_evidence: E,
}

/// One lifetime-bound borrow of the natural owners in the recovery delivery
/// graph. Release evidence is deliberately separate: ACK ingress supplies a
/// real sink while loss, migration, and early-data rejection use the ZST sink.
pub(in crate::conn) struct Graph<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> {
    egress: &'a mut output::Egress,
    control: &'a mut control::Pending,
    handshake: &'a mut tls::Handshake<DOMAIN>,
    streams: &'a mut State<B, D>,
    stream_events: &'a mut Pending,
}

impl<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> Graph<'a, DOMAIN, B, D> {
    pub(in crate::conn) fn new(
        egress: &'a mut output::Egress,
        ctrl: &'a mut control::Pending,
        hs: &'a mut tls::Handshake<DOMAIN>,
        state: &'a mut State<B, D>,
        events: &'a mut Pending,
    ) -> Self {
        Self {
            egress,
            control: ctrl,
            handshake: hs,
            streams: state,
            stream_events: events,
        }
    }
}

impl<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, E>
    Delivery<'a, DOMAIN, B, D, E>
{
    pub(super) fn new(graph: Graph<'a, DOMAIN, B, D>, proof: E) -> Self {
        let Graph {
            egress,
            control: ctrl,
            handshake: hs,
            streams: state,
            stream_events: events,
        } = graph;
        Self {
            egress,
            control: ctrl,
            handshake: hs,
            streams: state,
            stream_events: events,
            release_evidence: proof,
        }
    }

    pub(super) fn try_update(&mut self, now: time::Instant) -> Result<(), conn::Timing> {
        timer::Timer::try_update(self.egress, &self.handshake.keys, self.streams.local(), now)
    }
}

impl<const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, E: release::Sink>
    Delivery<'_, DOMAIN, B, D, E>
{
    pub(super) fn acknowledge(
        &mut self,
        epoch: conn::Epoch,
        pkt: journals::Packet,
        ctrls: stack::raw::Drain<'_, revision::Key, controls::Tag>,
        sends: stack::raw::Drain<'_, delivery::Handle<delivery::Stream>, streams::Tag>,
    ) -> Result<(), conn::Error> {
        self.egress.cc.packet_acked(
            pkt.bytes_sent as u64,
            pkt.sent_time,
            pkt.transmission.is_flight(),
            cc::Packet::from_epoch(epoch, pkt.pn),
        );
        self.ack(pkt, ctrls, sends)
    }

    pub(super) fn lose(
        &mut self,
        pkt: journals::Packet,
        ctrls: stack::raw::Drain<'_, revision::Key, controls::Tag>,
        sends: stack::raw::Drain<'_, delivery::Handle<delivery::Stream>, streams::Tag>,
    ) {
        if let Some(handle) = pkt.crypto {
            self.handshake.crypto.lose(handle);
        }
        for handle in ctrls {
            Records::new(&mut *self.control).lose(handle);
        }
        for handle in sends {
            self.streams.transmit.lose(handle);
        }
    }

    fn ack_ctrl(&mut self, handle: revision::Key) -> Result<(), conn::Error> {
        match Records::new(&mut *self.control).ack(handle) {
            control::Effect::None => Ok(()),
            control::Effect::RetireStream(id) => receive::Update::new(self.streams).retire_reset(
                self.stream_events,
                id,
                self.control,
            ),
        }
    }

    fn ack(
        &mut self,
        pkt: journals::Packet,
        ctrls: stack::raw::Drain<'_, revision::Key, controls::Tag>,
        sends: stack::raw::Drain<'_, delivery::Handle<delivery::Stream>, streams::Tag>,
    ) -> Result<(), conn::Error> {
        if let Some(handle) = pkt.crypto {
            self.handshake.crypto.acknowledge(handle);
        }
        for handle in ctrls {
            self.ack_ctrl(handle)?;
        }
        for handle in sends {
            receive::Update::new(self.streams).acknowledge(
                self.stream_events,
                handle,
                self.control,
                &mut self.release_evidence,
            );
        }
        Ok(())
    }
}
