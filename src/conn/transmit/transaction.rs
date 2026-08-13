use std::time;

use crate::conn::commit;
use crate::conn::control;
use crate::conn::delivery;
use crate::conn::journal;
use crate::conn::send;
use crate::conn::streams;

use crate::stream;

pub(super) struct Transaction<'a, const DOMAIN: u8, B: stream::ReceiveBuffer> {
    connection: &'a mut crate::conn::session::Connection<DOMAIN, B>,
}

impl<'a, const DOMAIN: u8, B: stream::ReceiveBuffer> Transaction<'a, DOMAIN, B> {
    pub(super) fn new(connection: &'a mut crate::conn::session::Connection<DOMAIN, B>) -> Self {
        Self { connection }
    }

    pub(super) fn datagram(&mut self, commit: &commit::Datagram, now: time::Instant) -> bool {
        if commit.in_flight {
            let mut packet = commit::Packet::new(crate::conn::Epoch::Application, commit.pn);
            packet.bytes = commit.bytes;
            packet.ack_eliciting = commit.datagram;
            packet.in_flight = true;
            packet.ack_included = commit.ack_included;
            packet.datagram = commit.datagram;
            return self.packet(&packet, now);
        }

        self.connection.egress.spaces[crate::conn::Epoch::Application as usize].next_pn =
            commit.pn.saturating_add(1);
        if commit.ack_included {
            self.connection.received[crate::conn::Epoch::Application as usize].ack_pending = false;
        }
        if commit.datagram {
            self.connection.egress.pending_datagrams.pop_front();
        }
        self.connection.egress.amplification_sent = self
            .connection
            .egress
            .amplification_sent
            .saturating_add(commit.bytes as u64);
        if commit.datagram && !self.connection.egress.ack_eliciting_sent_since_last_receive {
            self.connection.egress.last_activity = now;
            self.connection.egress.ack_eliciting_sent_since_last_receive = true;
        }
        true
    }

    pub(super) fn packet(&mut self, commit: &commit::Packet, now: time::Instant) -> bool {
        let epoch = commit.epoch;
        let pn = commit.pn;
        let tracked = commit.in_flight
            || !commit.controls.is_empty()
            || !commit.streams.is_empty()
            || commit.early_data
            || commit.crypto.is_some()
            || commit.pmtud_probe.is_some();
        let mut journal = journal::Packet {
            epoch,
            pn,
            sent_time: now,
            bytes_sent: commit.bytes,
            transmission: journal::Transmission::new(
                commit.early_data,
                commit.ack_eliciting,
                commit.in_flight,
            ),
            crypto: None,
        };
        self.connection.egress.spaces[epoch as usize].next_pn = pn.saturating_add(1);
        if commit.ack_included {
            self.connection.received[epoch as usize].ack_pending = false;
        }
        if let Some(delivery) = commit.crypto {
            let Some(handle) = self.connection.handshake.crypto_mut().commit(
                epoch,
                delivery.record,
                delivery.tracked,
            ) else {
                self.connection.egress.state = crate::conn::State::Closed;
                return false;
            };
            journal.crypto = Some(handle);
        }
        let journal_key = if tracked {
            let Some(key) = self.connection.egress.packet_journals.insert(journal) else {
                self.connection.egress.state = crate::conn::State::Closed;
                return false;
            };
            Some(key)
        } else {
            None
        };
        for delivery in commit.streams.as_slice().iter().copied() {
            let record = delivery.record;
            let handle = if let Some(handle) = delivery.tracked {
                if !self
                    .connection
                    .streams
                    .transmit
                    .deliveries
                    .add_carrier(handle)
                {
                    self.connection.egress.state = crate::conn::State::Closed;
                    return false;
                }
                handle
            } else {
                let streams::Streams {
                    state:
                        streams::State {
                            transmit:
                                streams::TransmitState {
                                    deliveries: stream_deliveries,
                                    schedule,
                                    map: streams_send,
                                    peer_total_sent,
                                    ..
                                },
                            ..
                        },
                    ..
                } = &mut self.connection.streams;
                let (handle, send_handle, deactivate) = {
                    let streams::table::Entry::Occupied(mut occupied) =
                        streams_send.entry(send::Id::new(record.stream_id))
                    else {
                        self.connection.egress.state = crate::conn::State::Closed;
                        return false;
                    };
                    let send_handle = occupied.handle();
                    let entry = occupied.get_mut();
                    let mut deactivate = false;
                    if entry.next_offset() == record.offset {
                        entry.advance_sent(record.len as usize, record.fin);
                        deactivate = !entry.has_pending() || entry.blocked();
                        *peer_total_sent = peer_total_sent.saturating_add(record.len);
                    }
                    let Some(handle) =
                        stream_deliveries.insert(send_handle, &mut entry.delivery_group, record)
                    else {
                        self.connection.egress.state = crate::conn::State::Closed;
                        return false;
                    };
                    (handle, send_handle, deactivate)
                };
                if deactivate {
                    schedule.deactivate(streams_send, send_handle);
                }
                handle
            };
            let Some(key) = journal_key else {
                self.connection.egress.state = crate::conn::State::Closed;
                return false;
            };
            if !self
                .connection
                .egress
                .packet_journals
                .push_stream(key, handle)
            {
                self.connection.egress.state = crate::conn::State::Closed;
                return false;
            }
        }
        for delivery in commit.controls.as_slice().iter().copied() {
            let record = delivery.record;
            let handle = control::delivery::Delivery::new(&mut self.connection.control).commit(
                epoch,
                record,
                delivery.handle,
            );
            let Some(handle) = handle else {
                self.connection.egress.state = crate::conn::State::Closed;
                return false;
            };
            if let delivery::Control::NewConnectionId(_) = record
                && let Some(key) = self.connection.control.local_cid_key(handle)
            {
                self.connection.path.local_cid_sent(key);
            }
            if let delivery::Control::PathChallenge(data) = record {
                self.connection.path.challenge_sent(data);
            }
            let Some(key) = journal_key else {
                self.connection.egress.state = crate::conn::State::Closed;
                return false;
            };
            if !self
                .connection
                .egress
                .packet_journals
                .push_control(key, handle)
            {
                self.connection.egress.state = crate::conn::State::Closed;
                return false;
            }
        }
        if tracked && commit.ack_eliciting {
            self.connection.egress.spaces[epoch as usize].time_of_last_ack_eliciting = Some(now);
            self.connection.egress.spaces[epoch as usize].ack_eliciting_in_flight += 1;
        }
        if commit.datagram {
            self.connection.egress.pending_datagrams.pop_front();
        }
        self.connection.egress.amplification_sent = self
            .connection
            .egress
            .amplification_sent
            .saturating_add(commit.bytes as u64);
        let bytes = commit.bytes as u64;
        self.connection
            .egress
            .cc
            .packet_sent(bytes, commit.in_flight);
        if commit.in_flight {
            let smoothed = self
                .connection
                .egress
                .rtt
                .smoothed_rtt
                .unwrap_or(crate::rtt::INITIAL_RTT);
            self.connection.egress.pacer.packet_sent(
                bytes,
                now,
                self.connection.egress.cc.cwnd,
                smoothed,
            );
        }
        if let Some(size) = commit.pmtud_probe {
            self.connection.egress.pmtud.arm_probe(size);
            self.connection.egress.pmtud_probe_pn = Some(pn);
        }
        if commit.pto_probe {
            self.connection.egress.pto_probe_allowance =
                self.connection.egress.pto_probe_allowance.saturating_sub(1);
            if self.connection.egress.pto_probe_allowance == 0 {
                self.connection.egress.pto_probe_epoch = None;
            }
        }
        if commit.ack_eliciting && !self.connection.egress.ack_eliciting_sent_since_last_receive {
            self.connection.egress.last_activity = now;
            self.connection.egress.ack_eliciting_sent_since_last_receive = true;
        }
        if commit.close {
            self.connection.egress.pending_close = None;
            self.connection.egress.state = crate::conn::State::Closed;
        }
        true
    }
}
