use std::mem;
use std::ops;

pub(in crate::conn) mod ack;
pub(super) mod application;
pub(in crate::conn) mod crypto;

use crate::frame;

use crate::stream;

use crate::conn;
use crate::conn::commit;
use crate::conn::control;
use crate::conn::delivery;
use crate::conn::packet;

use crate::conn::transmit::builder::application::one_rtt::BuildOneRtt as _;
use crate::conn::transmit::builder::application::zero_rtt::BuildZeroRtt as _;
use crate::conn::transmit::builder::crypto::Crypto as _;
use ack::Ack as _;

pub(in crate::conn) struct Builder<'a, const DOMAIN: u8, B: stream::ReceiveBuffer> {
    connection: &'a mut crate::conn::session::Connection<DOMAIN, B>,
}

impl<'a, const DOMAIN: u8, B: stream::ReceiveBuffer> Builder<'a, DOMAIN, B> {
    pub(in crate::conn) fn new(
        connection: &'a mut crate::conn::session::Connection<DOMAIN, B>,
    ) -> Self {
        Self { connection }
    }

    fn varint_len(value: usize) -> usize {
        if value < (1 << 6) {
            1
        } else if value < (1 << 14) {
            2
        } else if value < (1 << 30) {
            4
        } else {
            8
        }
    }

    fn long_payload_limit(fixed_header: usize, max_packet_bytes: usize) -> usize {
        let mut payload = max_packet_bytes.saturating_sub(fixed_header + conn::TAG_LEN + 1);
        loop {
            let length = conn::PN_LEN as usize + payload + conn::TAG_LEN;
            let next = max_packet_bytes
                .saturating_sub(fixed_header + conn::TAG_LEN + Self::varint_len(length));
            if next >= payload {
                return payload;
            }
            payload = next;
        }
    }

    fn initial_payload_limit(&self, max_packet_bytes: usize) -> usize {
        Self::initial_payload_limit_for(
            self.connection.path.peer_cid().len(),
            self.connection.path.local_cid().len(),
            self.connection.path.handshake.retry_token.len(),
            max_packet_bytes,
        )
    }

    pub(in crate::conn) fn initial_payload_limit_for(
        peer_cid_len: usize,
        local_cid_len: usize,
        token_len: usize,
        max_packet_bytes: usize,
    ) -> usize {
        let fixed_header = 1
            + 4
            + 1
            + peer_cid_len
            + 1
            + local_cid_len
            + Self::varint_len(token_len)
            + token_len
            + conn::PN_LEN as usize;
        Self::long_payload_limit(fixed_header, max_packet_bytes)
    }

    fn handshake_payload_limit(&self, max_packet_bytes: usize) -> usize {
        let fixed_header = 1
            + 4
            + 1
            + self.connection.path.peer_cid().len()
            + 1
            + self.connection.path.local_cid().len()
            + conn::PN_LEN as usize;
        Self::long_payload_limit(fixed_header, max_packet_bytes)
    }

    fn short_payload_limit(&self, max_packet_bytes: usize) -> usize {
        max_packet_bytes.saturating_sub(
            1 + self.connection.path.peer_cid().len() + conn::PN_LEN as usize + conn::TAG_LEN,
        )
    }

    fn append_frame(out: &mut Vec<u8>, limit: usize, frame: &frame::Frame) -> bool {
        let start = out.len();
        if frame.encode(out).is_ok() && out.len() <= limit {
            true
        } else {
            out.truncate(start);
            false
        }
    }

    fn append_stream_frame(
        out: &mut Vec<u8>,
        limit: usize,
        stream_id: u64,
        offset: u64,
        fin: bool,
        stream: &stream::Sender,
        len: usize,
    ) -> bool {
        let start = out.len();
        let Ok(len_u64) = u64::try_from(len) else {
            return false;
        };
        let Some(stream_id) = crate::varint::VarInt::new(stream_id) else {
            return false;
        };
        let Some(wire_offset) = crate::varint::VarInt::new(offset) else {
            return false;
        };
        if stream.range_available(offset, len_u64)
            && frame::Frame::encode_stream_header(out, stream_id, wire_offset, fin, Some(len))
                .is_ok()
            && out.len().saturating_add(len) <= limit
            && (len == 0 || stream.append_range(out, offset, len))
        {
            true
        } else {
            out.truncate(start);
            false
        }
    }

    fn can_track_packet(&self) -> bool {
        let pn = self.connection.egress.recovery.spaces[conn::Epoch::Application as usize].next_pn;
        self.connection
            .egress
            .recovery
            .packet_journals
            .has_room_for(conn::Epoch::Application, pn, 2)
            && self
                .connection
                .egress
                .recovery
                .packet_journals
                .has_carrier_room(
                    conn::PACKET_CONTROL_CAPACITY * 2,
                    conn::PACKET_STREAM_CAPACITY * 2,
                )
            && self.connection.handshake.crypto().has_room(2)
            && (self.connection.streams.transmit.deliveries.has_retransmit()
                || self
                    .connection
                    .streams
                    .transmit
                    .deliveries
                    .has_room(conn::PACKET_STREAM_CAPACITY * 2))
    }

    fn can_track_probe(&self, epoch: conn::Epoch) -> bool {
        let pn = self.connection.egress.recovery.spaces[epoch as usize].next_pn;
        self.connection
            .egress
            .recovery
            .packet_journals
            .has_room_for(epoch, pn, 1)
            && (epoch != conn::Epoch::Application
                || self
                    .connection
                    .egress
                    .recovery
                    .packet_journals
                    .has_carrier_room(conn::PACKET_CONTROL_CAPACITY, conn::PACKET_STREAM_CAPACITY))
    }

    fn append_pending_controls<const MASK: u16, Out>(
        pending: &control::Pending,
        path: &crate::conn::path::Path,
        out: &mut Out,
        limit: usize,
        commit: &mut commit::Packet,
        mut cursor: control::cursor::Cursor<'_, MASK>,
    ) where
        Out: ops::Deref<Target = Vec<u8>> + ops::DerefMut,
    {
        while !commit.controls.is_full() {
            let Some((handle, record)) = cursor.next() else {
                break;
            };
            if !control::encode::Encoder::new(pending, path)
                .encode_pending::<MASK, _>(out, limit, handle, record)
            {
                break;
            }
            commit.push_control_delivery(record, handle);
            commit.properties.ack_eliciting = true;
        }
    }

    fn append_path_controls<Out>(
        pending: &control::Pending,
        path: &crate::conn::path::Path,
        records: impl Iterator<Item = (delivery::Handle<delivery::Control>, delivery::Control)>,
        out: &mut Out,
        limit: usize,
        commit: &mut commit::Packet,
    ) where
        Out: ops::Deref<Target = Vec<u8>> + ops::DerefMut,
    {
        for (handle, record) in records {
            if commit.controls.is_full() {
                break;
            }
            if !control::encode::Encoder::new(pending, path)
                .encode_pending::<{ control::SUFFIX }, _>(out, limit, handle, record)
            {
                break;
            }
            commit.push_control_delivery(record, handle);
            commit.properties.ack_eliciting = true;
        }
    }

    pub(super) fn build_pto_probe(
        &mut self,
        dst: &mut Vec<u8>,
        max_packet_bytes: usize,
    ) -> Option<(usize, commit::Packet)> {
        let epoch = self.connection.egress.recovery.pto_probe_epoch?;
        if !self.can_track_probe(epoch) {
            return None;
        }
        match epoch {
            conn::Epoch::Initial | conn::Epoch::Handshake => self.build_crypto_packet(
                dst,
                max_packet_bytes,
                self.connection.egress.recovery.pto_probe_epoch?,
                packet::CryptoMode::PtoProbe,
            ),
            conn::Epoch::Application
                if self
                    .connection
                    .handshake
                    .write_key(conn::Epoch::Application)
                    .is_some() =>
            {
                application::Application::new(self.connection)
                    .build_one_rtt::<true>(dst, max_packet_bytes)
            }
            conn::Epoch::Application => application::Application::new(self.connection)
                .build_zero_rtt(dst, max_packet_bytes, true),
        }
    }

    fn seal_crypto_packet(
        &mut self,
        dst: &mut Vec<u8>,
        epoch: conn::Epoch,
        pn: u64,
        frames: &[u8],
    ) -> Option<usize> {
        let packet_type = match epoch {
            conn::Epoch::Initial => crate::packet::LONG_INITIAL,
            conn::Epoch::Handshake => crate::packet::LONG_HANDSHAKE,
            conn::Epoch::Application => return None,
        };
        let mut header = mem::take(&mut self.connection.scratch.header);
        header.clear();
        let token = (epoch == conn::Epoch::Initial)
            .then_some(self.connection.path.handshake.retry_token.as_slice());
        let result = crate::packet::LongHeader {
            version: crate::packet::QUIC_V1,
            packet_type,
            dcid: self.connection.path.peer_cid(),
            scid: self.connection.path.local_cid(),
            token,
            packet_number: pn,
            packet_number_len: conn::PN_LEN,
        }
        .encode_into(&mut header, frames.len() + conn::TAG_LEN)
        .ok()
        .and_then(|pn_offset| {
            let protection = match epoch {
                conn::Epoch::Initial | conn::Epoch::Handshake => {
                    self.connection.handshake.write_key(epoch)
                }
                conn::Epoch::Application => None,
            }?;
            protection
                .encrypt_long_into(dst, &header, frames, pn, pn_offset, conn::PN_LEN as usize)
                .ok()
        });
        header.clear();
        self.connection.scratch.header = header;
        result
    }

    pub(super) fn build_crypto_packet(
        &mut self,
        dst: &mut Vec<u8>,
        max_packet_bytes: usize,
        epoch: conn::Epoch,
        mode: packet::CryptoMode,
    ) -> Option<(usize, commit::Packet)> {
        if epoch == conn::Epoch::Application
            || epoch == conn::Epoch::Initial
                && self.connection.peer.is_client
                && max_packet_bytes < crate::conn::MIN_INITIAL_LEN
        {
            return None;
        }
        match epoch {
            conn::Epoch::Initial | conn::Epoch::Handshake => {
                self.connection.handshake.write_key(epoch)?
            }
            conn::Epoch::Application => return None,
        };
        let payload_limit = match epoch {
            conn::Epoch::Initial => self.initial_payload_limit(max_packet_bytes),
            conn::Epoch::Handshake => self.handshake_payload_limit(max_packet_bytes),
            conn::Epoch::Application => return None,
        };
        let pn = self.connection.egress.recovery.spaces[epoch as usize].next_pn;

        let mut frames = mem::take(&mut self.connection.scratch.frames);
        frames.clear();
        let ack_included = self.append_ack_frame(epoch, &mut frames, payload_limit);
        let frame_room = payload_limit.saturating_sub(frames.len());
        let mut crypto = None;
        match mode {
            packet::CryptoMode::Regular => {
                if self
                    .connection
                    .egress
                    .recovery
                    .packet_journals
                    .has_room_for(epoch, pn, 2)
                    && self.connection.handshake.crypto().has_room(2)
                {
                    let chunk = match epoch {
                        conn::Epoch::Initial => Self::peek_crypto_chunk(
                            self.connection.handshake.crypto(),
                            conn::Epoch::Initial,
                            frame_room,
                        ),
                        conn::Epoch::Handshake => Self::peek_crypto_chunk(
                            self.connection.handshake.crypto(),
                            conn::Epoch::Handshake,
                            frame_room,
                        ),
                        conn::Epoch::Application => None,
                    };
                    if let Some((record, data)) = chunk
                        && Self::encode_crypto(&mut frames, record.record.offset, data)
                    {
                        crypto = Some(record);
                    }
                }
            }
            packet::CryptoMode::PtoProbe => {
                if let Some((delivery, data)) = self.crypto_probe(epoch, frame_room)
                    && Self::encode_crypto(&mut frames, delivery.record.offset, data)
                {
                    crypto = Some(delivery);
                } else {
                    frames.push(crate::frame::TYPE_PING);
                }
            }
        }

        if mode == packet::CryptoMode::Regular && frames.is_empty() {
            self.connection.scratch.frames = frames;
            return None;
        }

        if epoch == conn::Epoch::Initial
            && self.connection.peer.is_client
            && frames.len() < payload_limit
        {
            frames.resize(payload_limit, 0);
        }
        let sealed = self.seal_crypto_packet(dst, epoch, pn, &frames);
        frames.clear();
        self.connection.scratch.frames = frames;
        let n = sealed?;
        let mut commit = commit::Packet::new(epoch, pn);
        commit.bytes = n;
        commit.properties.ack_eliciting = mode == packet::CryptoMode::PtoProbe || crypto.is_some();
        commit.properties.in_flight = commit.properties.ack_eliciting;
        commit.properties.ack_included = ack_included;
        commit.crypto = crypto;
        commit.properties.pto_probe = mode == packet::CryptoMode::PtoProbe;
        Some((n, commit))
    }
}
