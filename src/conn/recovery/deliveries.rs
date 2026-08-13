use crate::{conn, stream};

pub(super) struct Deliveries<'a, const DOMAIN: u8, B: stream::ReceiveBuffer, C> {
    pub(super) egress: &'a mut conn::egress::Egress,
    pub(super) control: &'a mut C,
    pub(super) handshake: &'a mut conn::handshake::Handshake<DOMAIN>,
    pub(super) streams: &'a mut conn::streams::State<B>,
    pub(super) stream_events: &'a mut conn::event_queue::Events,
    pub(super) is_client: bool,
}

impl<'a, const DOMAIN: u8, B: stream::ReceiveBuffer, C> Deliveries<'a, DOMAIN, B, C> {
    pub(super) fn new(
        egress: &'a mut conn::egress::Egress,
        control: &'a mut C,
        handshake: &'a mut conn::handshake::Handshake<DOMAIN>,
        streams: &'a mut conn::streams::State<B>,
        stream_events: &'a mut conn::event_queue::Events,
        is_client: bool,
    ) -> Self {
        Self {
            egress,
            control,
            handshake,
            streams,
            stream_events,
            is_client,
        }
    }
}

impl<const DOMAIN: u8, B: stream::ReceiveBuffer, C: conn::control::Write>
    Deliveries<'_, DOMAIN, B, C>
{
    pub(super) fn acknowledge(
        &mut self,
        epoch: conn::Epoch,
        journal: conn::journal::Packet,
        controls: conn::journal::ControlDrain<'_>,
        streams: conn::journal::StreamDrain<'_>,
    ) {
        self.egress
            .cc
            .packet_acked(journal.bytes_sent as u64, journal.in_flight);
        if epoch == conn::Epoch::Application && Some(journal.pn) == self.egress.pmtud_probe_pn {
            self.egress.pmtud.probe_acked();
            self.egress.pmtud_probe_pn = None;
        }
        if journal.ack_eliciting && journal.in_flight {
            self.egress.spaces[epoch as usize].ack_eliciting_in_flight = self.egress.spaces
                [epoch as usize]
                .ack_eliciting_in_flight
                .saturating_sub(1);
        }
        self.acknowledge_deliveries(journal, controls, streams);
    }

    pub(super) fn lose(
        &mut self,
        journal: conn::journal::Packet,
        controls: conn::journal::ControlDrain<'_>,
        streams: conn::journal::StreamDrain<'_>,
    ) {
        if let Some(handle) = journal.crypto {
            self.handshake.crypto_mut().lose(handle);
        }
        for handle in controls {
            self.control.lose_control(handle);
        }
        for handle in streams {
            self.streams.transmit.deliveries.lose(handle);
        }
    }

    fn acknowledge_control(&mut self, handle: conn::delivery::Handle<conn::delivery::Control>) {
        match self.control.acknowledge_control(handle) {
            conn::control::Effect::None => {}
            conn::control::Effect::RetireStream(stream_id) => self.streams.retire_send_reserved(
                self.stream_events,
                stream_id,
                self.is_client,
                self.control,
            ),
        }
    }

    fn acknowledge_deliveries(
        &mut self,
        journal: conn::journal::Packet,
        controls: conn::journal::ControlDrain<'_>,
        streams: conn::journal::StreamDrain<'_>,
    ) {
        if let Some(handle) = journal.crypto {
            self.handshake.crypto_mut().acknowledge(handle);
        }
        for handle in controls {
            self.acknowledge_control(handle);
        }
        for handle in streams {
            let outcome = {
                let conn::streams::State {
                    transmit:
                        conn::streams::TransmitState {
                            deliveries, map, ..
                        },
                    ..
                } = &mut self.streams;
                let Some(acknowledged) = deliveries.acknowledge(handle) else {
                    continue;
                };
                let send_handle = acknowledged.send_handle();
                match map.resolve_mut(send_handle) {
                    Some((stream_id, entry)) => acknowledged
                        .commit(&mut entry.stream)
                        .map(|retire| retire.then_some(stream_id)),
                    None => {
                        acknowledged.cancel();
                        Ok(None)
                    }
                }
            };
            match outcome {
                Ok(Some(stream_id)) => self.streams.retire_send_reserved(
                    self.stream_events,
                    stream_id,
                    self.is_client,
                    self.control,
                ),
                Ok(None) => {}
                Err(_) => {
                    self.egress.state = conn::State::Closed;
                    return;
                }
            }
        }
    }
}
