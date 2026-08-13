use std::time::Instant;

use crate::conn::receive_workspace::ParsedAckRanges;
use crate::conn::{Epoch, Error, MAX_FRAMES_PER_PACKET, handshake};
use crate::frame::{Frame, TYPE_PADDING};
use crate::stream::ReceiveBuffer;

use super::Ingress;
use super::admitted_packet::AdmittedPacket;

mod commit;
mod plan;
mod source;

use commit::Commit as _;
use source::Source;
pub(super) use source::{Copied, Retained};

#[derive(Clone, Copy)]
pub(super) struct PacketCid<'a> {
    pub(super) routed: Option<crate::conn::path::LocalCidKey>,
    pub(super) bytes: &'a [u8],
}

#[derive(Clone, Copy)]
pub(super) struct PacketMeta {
    pub(super) epoch: Epoch,
    pub(super) pn: u64,
    pub(super) now: Instant,
}

impl PacketMeta {
    pub(super) const fn new(epoch: Epoch, pn: u64, now: Instant) -> Self {
        Self { epoch, pn, now }
    }
}

pub(super) enum PacketDisposition {
    Commit,
    Drop,
}

pub(super) trait ProcessFrames<const DOMAIN: u8, B: ReceiveBuffer> {
    fn process_packet_body<R, S>(
        &mut self,
        meta: PacketMeta,
        packet_cid: Option<PacketCid<'_>>,
        body: &[u8],
        read: &mut R,
        source: &mut S,
    ) -> Result<(), Error>
    where
        R: handshake::Reader<DOMAIN>,
        S: Source<B>;
}

impl<const DOMAIN: u8, B: ReceiveBuffer> ProcessFrames<DOMAIN, B> for Ingress<'_, DOMAIN, B> {
    fn process_packet_body<R, S>(
        &mut self,
        meta: PacketMeta,
        packet_cid: Option<PacketCid<'_>>,
        body: &[u8],
        read: &mut R,
        source: &mut S,
    ) -> Result<(), Error>
    where
        R: handshake::Reader<DOMAIN>,
        S: Source<B>,
    {
        let Some(mut packet) = AdmittedPacket::begin(self.connection, meta.epoch, meta.pn) else {
            return Ok(());
        };
        let datagram_slots = {
            let (connection, _) = packet.state();
            connection
                .incoming_datagrams_capacity
                .saturating_sub(connection.incoming_datagrams.len())
        };
        let mut plan = plan::Plan::begin(self.workspace, datagram_slots);

        let mut position = 0;
        let mut ack_eliciting = false;
        let body_start = body.as_ptr() as usize;
        let mut parse_error = None;
        let mut plan_error = None;
        while position < body.len() {
            if body[position] == TYPE_PADDING {
                position += body[position..]
                    .iter()
                    .take_while(|&&byte| byte == TYPE_PADDING)
                    .count();
                continue;
            }
            if plan.frame_len() == MAX_FRAMES_PER_PACKET {
                parse_error = Some(Error::FrameDecode);
                break;
            }
            let decoded = crate::frame::decode::FrameDecoder::new(
                &body[position..],
                |data: &[u8]| {
                    let start = data.as_ptr() as usize - body_start;
                    start..start + data.len()
                },
                |ranges: &[u8], count| {
                    let start = ranges.as_ptr() as usize - body_start;
                    ParsedAckRanges {
                        bytes: start..start + ranges.len(),
                        count,
                    }
                },
            )
            .decode();
            let (frame, consumed) = match decoded {
                Ok(decoded) => decoded,
                Err(_) => {
                    parse_error = Some(Error::FrameDecode);
                    break;
                }
            };
            if consumed == 0 {
                parse_error = Some(Error::FrameDecode);
                break;
            }
            if !matches!(
                &frame,
                Frame::Ack { .. } | Frame::Padding | Frame::ConnectionClose { .. }
            ) {
                ack_eliciting = true;
            }
            let frame_index = plan.frame_len();
            if plan_error.is_none() {
                plan_error = plan.record(meta.epoch, frame_index, &frame).err();
            }
            plan.push_frame(frame);
            position += consumed;
        }
        if let Some(error) = parse_error {
            packet.close();
            return Err(error);
        }

        let result = match plan_error {
            Some(Error::EventCapacity | Error::StreamBufferExceeded) => Ok(PacketDisposition::Drop),
            Some(error) => Err(error),
            None => packet.process(meta, packet_cid, body, read, &mut plan, source),
        };
        drop(plan);
        match result {
            Ok(PacketDisposition::Commit) => {
                packet.commit(ack_eliciting, meta.now);
                Ok(())
            }
            Ok(PacketDisposition::Drop) => Ok(()),
            Err(error) => {
                packet.close();
                Err(error)
            }
        }
    }
}
