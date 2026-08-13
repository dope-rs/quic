use crate::conn;
use crate::conn::receive_workspace;
use crate::frame;
use crate::stream;

pub(super) struct Reservation {
    pub(super) admitted_bytes: usize,
    pub(super) event_slots: usize,
}

fn stop_frame_id(frame: &receive_workspace::ParsedFrame) -> Option<u64> {
    match frame {
        frame::Frame::StopSending { stream_id, .. } => Some(stream_id.get()),
        _ => None,
    }
}

/// Scratch-backed packet plan whose workspace borrow prevents reentrancy.
/// Dropping it empties every bounded scratch structure for reuse.
pub(super) struct Plan<'workspace> {
    workspace: &'workspace mut conn::ReceiveWorkspace,
    admitted_bytes: usize,
    datagram_slots: usize,
}

impl<'workspace> Plan<'workspace> {
    pub(super) fn stream_frame_id(frame: &receive_workspace::ParsedFrame) -> Option<u64> {
        match frame {
            frame::Frame::Stream { stream_id, .. }
            | frame::Frame::ResetStream { stream_id, .. } => Some(stream_id.get()),
            _ => None,
        }
    }

    pub(super) fn begin(
        workspace: &'workspace mut conn::ReceiveWorkspace,
        datagram_slots: usize,
    ) -> Self {
        workspace.parsed_frames.clear();
        workspace.admissions.clear();
        workspace.payloads.clear();
        workspace.stream_frames.clear();
        workspace.stop_frames.clear();
        workspace.segments.clear();
        workspace.parts.clear();
        Self {
            workspace,
            admitted_bytes: 0,
            datagram_slots,
        }
    }

    pub(super) fn record(
        &mut self,
        epoch: conn::Epoch,
        frame_index: usize,
        frame: &receive_workspace::ParsedFrame,
    ) -> Result<(), conn::Error> {
        self.workspace.admissions.push(frame_index);
        self.workspace.payloads.push(frame_index);
        match frame {
            frame::Frame::Datagram { data, .. }
                if epoch == conn::Epoch::Application && self.datagram_slots != 0 =>
            {
                self.workspace
                    .admissions
                    .mark(frame_index, receive_workspace::ReceiveAdmission::Datagram);
                self.workspace
                    .payloads
                    .set_accepted(frame_index, data.len())
                    .ok_or(conn::Error::StreamBufferExceeded)?;
                self.admitted_bytes = self
                    .admitted_bytes
                    .checked_add(data.len())
                    .ok_or(conn::Error::StreamBufferExceeded)?;
                self.datagram_slots -= 1;
            }
            frame::Frame::Stream { .. } | frame::Frame::ResetStream { .. }
                if epoch == conn::Epoch::Application =>
            {
                let frame_index =
                    crate::conn::receive_workspace::StreamFrameIndex::new(frame_index)
                        .ok_or(conn::Error::FrameDecode)?;
                if !self.workspace.stream_frames.push(frame_index) {
                    return Err(conn::Error::FrameDecode);
                }
            }
            frame::Frame::StopSending { .. } if epoch == conn::Epoch::Application => {
                let frame_index = crate::conn::receive_workspace::StopFrameIndex::new(frame_index)
                    .ok_or(conn::Error::FrameDecode)?;
                if !self.workspace.stop_frames.push(frame_index) {
                    return Err(conn::Error::FrameDecode);
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub(super) fn reserve<B: stream::ReceiveBuffer>(
        &mut self,
        streams: &mut crate::conn::streams::State<B>,
        is_client: bool,
    ) -> Result<Reservation, conn::Error> {
        let conn::ReceiveWorkspace {
            parsed_frames,
            admissions,
            payloads,
            stream_frames,
            stop_frames,
            segments,
            parts,
        } = &mut *self.workspace;
        let stream_frames = stream_frames.as_mut_slice();
        let stop_frames = stop_frames.as_mut_slice();
        stream_frames.sort_unstable_by_key(|&frame_index| {
            (
                Self::stream_frame_id(&parsed_frames[frame_index.get()]).unwrap_or(u64::MAX),
                frame_index,
            )
        });
        stop_frames.sort_unstable_by_key(|&frame_index| {
            (
                stop_frame_id(&parsed_frames[frame_index.get()]).unwrap_or(u64::MAX),
                frame_index,
            )
        });

        let mut admitted_bytes = self.admitted_bytes;
        let mut receive_stream_slots = 0usize;
        let mut receive_range_slots = 0usize;
        let mut send_stream_slots = 0usize;
        let mut event_slots = 0usize;
        let mut flow_control_bytes = 0u64;
        let mut group_start = 0;
        while group_start < stream_frames.len() {
            let stream_id = Self::stream_frame_id(&parsed_frames[stream_frames[group_start].get()])
                .ok_or(conn::Error::FrameDecode)?;
            let group_end = stream_frames[group_start..]
                .iter()
                .position(|&frame_index| {
                    Self::stream_frame_id(&parsed_frames[frame_index.get()]) != Some(stream_id)
                })
                .map_or(stream_frames.len(), |offset| group_start + offset);
            let impact = streams.plan_stream_frames(
                crate::conn::streams::receive::FrameGroup::new(
                    &stream_frames[group_start..group_end],
                    parsed_frames,
                ),
                crate::conn::streams::receive::PlanContext::new(
                    admissions, payloads, segments, parts, is_client,
                ),
            )?;
            admitted_bytes = admitted_bytes
                .checked_add(impact.accepted_bytes)
                .ok_or(conn::Error::StreamBufferExceeded)?;
            receive_stream_slots = receive_stream_slots
                .checked_add(impact.stream_slots)
                .ok_or(conn::Error::StreamBufferExceeded)?;
            receive_range_slots = receive_range_slots
                .checked_add(impact.range_slots)
                .ok_or(conn::Error::StreamBufferExceeded)?;
            event_slots = event_slots
                .checked_add(impact.event_slots)
                .ok_or(conn::Error::EventCapacity)?;
            flow_control_bytes = flow_control_bytes
                .checked_add(impact.flow_control_bytes)
                .ok_or(conn::Error::FlowControl)?;
            group_start = group_end;
        }

        group_start = 0;
        while group_start < stop_frames.len() {
            let stream_id = stop_frame_id(&parsed_frames[stop_frames[group_start].get()])
                .ok_or(conn::Error::FrameDecode)?;
            let group_end = stop_frames[group_start..]
                .iter()
                .position(|&frame_index| {
                    stop_frame_id(&parsed_frames[frame_index.get()]) != Some(stream_id)
                })
                .map_or(stop_frames.len(), |offset| group_start + offset);
            let impact = streams.plan_stop(stream_id, is_client)?;
            if impact.active {
                for &frame_index in &stop_frames[group_start..group_end] {
                    admissions.mark(frame_index.get(), receive_workspace::ReceiveAdmission::Stop);
                }
            }
            send_stream_slots = send_stream_slots
                .checked_add(impact.stream_slots)
                .ok_or(conn::Error::StreamBufferExceeded)?;
            event_slots = event_slots
                .checked_add(impact.event_slots)
                .ok_or(conn::Error::EventCapacity)?;
            group_start = group_end;
        }

        if receive_stream_slots > streams.receive.map.remaining_capacity()
            || receive_range_slots > streams.receive.ranges.remaining_capacity()
            || send_stream_slots > streams.transmit.map.remaining_capacity()
        {
            return Err(conn::Error::StreamBufferExceeded);
        }
        if streams
            .receive
            .total
            .checked_add(flow_control_bytes)
            .is_none_or(|total| total > streams.receive.local_max_data)
        {
            return Err(conn::Error::FlowControl);
        }
        Ok(Reservation {
            admitted_bytes,
            event_slots,
        })
    }

    pub(super) fn frame_len(&self) -> usize {
        self.workspace.parsed_frames.len()
    }

    pub(super) fn push_frame(&mut self, frame: receive_workspace::ParsedFrame) {
        self.workspace.parsed_frames.push(frame);
    }

    pub(super) fn workspace(&mut self) -> &mut conn::ReceiveWorkspace {
        self.workspace
    }
}

impl Drop for Plan<'_> {
    fn drop(&mut self) {
        self.workspace.parsed_frames.clear();
        self.workspace.admissions.clear();
        self.workspace.payloads.clear();
        self.workspace.stream_frames.clear();
        self.workspace.stop_frames.clear();
        self.workspace.segments.clear();
        self.workspace.parts.clear();
    }
}
