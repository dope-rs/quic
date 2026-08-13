use std::ops::Range;

use crate::frame::Frame;

use super::MAX_FRAMES_PER_PACKET;

#[derive(Clone)]
pub(crate) struct ParsedAckRanges {
    pub(crate) bytes: Range<usize>,
    pub(crate) count: usize,
}

pub(crate) type ParsedFrame = Frame<Range<usize>, ParsedAckRanges>;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum ReceiveAdmission {
    #[default]
    Drop,
    Datagram,
    Stream,
    StreamTransient,
    Reset,
    Stop,
}

pub(crate) struct ReceiveAdmissions {
    values: [ReceiveAdmission; MAX_FRAMES_PER_PACKET],
    len: usize,
}

impl ReceiveAdmissions {
    pub(crate) fn push(&mut self, frame_index: usize) {
        debug_assert_eq!(self.len, frame_index);
        debug_assert!(frame_index < MAX_FRAMES_PER_PACKET);
        self.values[frame_index] = ReceiveAdmission::Drop;
        self.len += 1;
    }

    pub(crate) fn mark(&mut self, frame_index: usize, admission: ReceiveAdmission) {
        debug_assert!(admission != ReceiveAdmission::Drop);
        debug_assert_eq!(self.get(frame_index), ReceiveAdmission::Drop);
        self.values[frame_index] = admission;
    }

    pub(crate) fn get(&self, frame_index: usize) -> ReceiveAdmission {
        debug_assert!(frame_index < self.len);
        self.values[frame_index]
    }

    pub(crate) fn clear(&mut self) {
        self.len = 0;
    }
}

impl Default for ReceiveAdmissions {
    fn default() -> Self {
        Self {
            values: [ReceiveAdmission::Drop; MAX_FRAMES_PER_PACKET],
            len: 0,
        }
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct ReceivePayloadPlan {
    start: u32,
    accepted: u32,
}

impl ReceivePayloadPlan {
    pub(crate) fn accepted(self) -> usize {
        self.accepted as usize
    }

    pub(crate) fn compact_range(self) -> Range<usize> {
        let start = self.start as usize;
        start..start + self.accepted as usize
    }
}

pub(crate) struct ReceivePayloadPlans {
    values: [ReceivePayloadPlan; MAX_FRAMES_PER_PACKET],
    len: usize,
}

impl ReceivePayloadPlans {
    pub(crate) fn push(&mut self, frame_index: usize) {
        debug_assert_eq!(self.len, frame_index);
        self.values[frame_index] = ReceivePayloadPlan::default();
        self.len += 1;
    }

    pub(crate) fn set_accepted(&mut self, frame_index: usize, accepted: usize) -> Option<()> {
        self.values.get_mut(frame_index)?.accepted = u32::try_from(accepted).ok()?;
        Some(())
    }

    pub(crate) fn set_start(&mut self, frame_index: usize, start: usize) -> Option<()> {
        self.values.get_mut(frame_index)?.start = u32::try_from(start).ok()?;
        Some(())
    }

    pub(crate) fn get(&self, frame_index: usize) -> ReceivePayloadPlan {
        debug_assert!(frame_index < self.len);
        self.values[frame_index]
    }

    pub(crate) fn clear(&mut self) {
        self.len = 0;
    }
}

impl Default for ReceivePayloadPlans {
    fn default() -> Self {
        Self {
            values: [ReceivePayloadPlan::default(); MAX_FRAMES_PER_PACKET],
            len: 0,
        }
    }
}

const _: () = assert!(std::mem::size_of::<ReceiveAdmission>() == 1);

#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
struct FrameIndex(u8);

impl FrameIndex {
    fn new(index: usize) -> Option<Self> {
        u8::try_from(index).ok().map(Self)
    }

    fn get(self) -> usize {
        self.0 as usize
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub(crate) struct StreamFrameIndex(FrameIndex);

impl StreamFrameIndex {
    pub(crate) fn new(index: usize) -> Option<Self> {
        FrameIndex::new(index).map(Self)
    }

    pub(crate) fn get(self) -> usize {
        self.0.get()
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub(crate) struct StopFrameIndex(FrameIndex);

impl StopFrameIndex {
    pub(crate) fn new(index: usize) -> Option<Self> {
        FrameIndex::new(index).map(Self)
    }

    pub(crate) fn get(self) -> usize {
        self.0.get()
    }
}

const _: () = assert!(std::mem::size_of::<StreamFrameIndex>() == 1);
const _: () = assert!(std::mem::size_of::<StopFrameIndex>() == 1);

pub(crate) struct FrameIndices<I: Copy> {
    values: [I; MAX_FRAMES_PER_PACKET],
    len: usize,
}

impl<I: Copy + Default> Default for FrameIndices<I> {
    fn default() -> Self {
        Self {
            values: [I::default(); MAX_FRAMES_PER_PACKET],
            len: 0,
        }
    }
}

impl<I: Copy> FrameIndices<I> {
    pub(crate) fn push(&mut self, value: I) -> bool {
        let Some(slot) = self.values.get_mut(self.len) else {
            return false;
        };
        *slot = value;
        self.len += 1;
        true
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [I] {
        &mut self.values[..self.len]
    }

    pub(crate) fn clear(&mut self) {
        self.len = 0;
    }
}

/// Bounded metadata storage shared by one serialized receive lane.
/// It never owns packet payloads; its exclusive borrow prevents reentrancy.
pub struct ReceiveWorkspace {
    pub(super) parsed_frames: Vec<ParsedFrame>,
    pub(super) admissions: ReceiveAdmissions,
    pub(super) payloads: ReceivePayloadPlans,
    pub(super) stream_frames: FrameIndices<StreamFrameIndex>,
    pub(super) stop_frames: FrameIndices<StopFrameIndex>,
    pub(super) segments: Vec<Range<u64>>,
    pub(super) parts: Vec<(u64, Range<usize>)>,
}

impl ReceiveWorkspace {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for ReceiveWorkspace {
    fn default() -> Self {
        Self {
            parsed_frames: Vec::with_capacity(MAX_FRAMES_PER_PACKET),
            admissions: ReceiveAdmissions::default(),
            payloads: ReceivePayloadPlans::default(),
            stream_frames: FrameIndices::default(),
            stop_frames: FrameIndices::default(),
            segments: Vec::with_capacity(crate::range_buffer::MAX_RANGES),
            parts: Vec::with_capacity(crate::range_buffer::MAX_RANGES),
        }
    }
}
