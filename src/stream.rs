use std::mem::size_of;
use std::ops::Range;

use o3::buffer::{
    CapacityError,
    bytes::{Bytes, Retained},
    queue::Cursor,
    storage::{self, inline},
};

use crate::range_buffer::{Arena, InsertError, MAX_RANGES, RangeBuffer, ReadySegments};

const MAX_RECV_SEGMENTS: usize = MAX_RANGES;

mod receive_buffer {
    pub trait Sealed {}
}

/// Receive storage that can preserve a packet owner's lifetime while exposing
/// only the accepted byte range.
pub trait ReceiveBuffer: receive_buffer::Sealed + AsRef<[u8]> + Sized {
    #[doc(hidden)]
    type Ready: ReadyBuffer<Self>;
    #[doc(hidden)]
    const SEGMENTED_READY: bool;
    fn copy_from_slice(bytes: &[u8]) -> Self;
    #[doc(hidden)]
    fn insert_copied(
        stream: &mut RecvStream<Self>,
        arena: &mut Arena<Self>,
        parts: &mut Vec<(u64, Range<usize>)>,
        offset: u64,
        bytes: &[u8],
        fin: bool,
    ) -> Result<(), RecvError> {
        stream.insert(arena, parts, offset, Self::copy_from_slice(bytes), fin)
    }
    fn from_vec(bytes: Vec<u8>) -> Self {
        Self::copy_from_slice(&bytes)
    }
    fn slice(&self, range: Range<usize>) -> Self;
    fn into_range(self, range: Range<usize>) -> Self {
        self.slice(range)
    }
    fn into_suffix(self, offset: usize) -> Self;
    fn into_vec(self) -> Vec<u8>;
}

/// Type-selected contiguous receive storage.
///
/// This is public only because it is the associated implementation detail of
/// [`ReceiveBuffer`]. Applications should consume data through stream APIs.
#[doc(hidden)]
pub trait ReadyBuffer<B: ReceiveBuffer>: Default {
    fn clear(&mut self, arena: &mut Arena<B>);
    fn len(&self) -> usize;
    fn segment_count(&self) -> usize;
    fn try_push_back(&mut self, arena: &mut Arena<B>, buffer: B) -> Result<(), B>;
    fn read_into(&mut self, arena: &mut Arena<B>, destination: &mut Vec<u8>) -> usize;
    fn read_owned(&mut self, arena: &mut Arena<B>) -> Option<Vec<u8>>;
    fn pop_front(&mut self, arena: &mut Arena<B>) -> Option<B>;
}

impl receive_buffer::Sealed for Vec<u8> {}

impl ReceiveBuffer for Vec<u8> {
    type Ready = Vec<u8>;
    const SEGMENTED_READY: bool = false;

    fn copy_from_slice(bytes: &[u8]) -> Self {
        bytes.to_vec()
    }

    fn insert_copied(
        stream: &mut RecvStream<Self>,
        arena: &mut Arena<Self>,
        parts: &mut Vec<(u64, Range<usize>)>,
        offset: u64,
        bytes: &[u8],
        fin: bool,
    ) -> Result<(), RecvError> {
        stream.insert_copy(arena, parts, offset, bytes, fin)
    }

    fn from_vec(bytes: Vec<u8>) -> Self {
        bytes
    }

    fn slice(&self, range: Range<usize>) -> Self {
        self[range].to_vec()
    }

    fn into_range(mut self, range: Range<usize>) -> Self {
        self.truncate(range.end);
        self.into_suffix(range.start)
    }

    fn into_suffix(mut self, offset: usize) -> Self {
        if offset == 0 {
            self
        } else {
            self.split_off(offset)
        }
    }

    fn into_vec(self) -> Vec<u8> {
        self
    }
}

impl ReadyBuffer<Vec<u8>> for Vec<u8> {
    fn clear(&mut self, _arena: &mut Arena<Vec<u8>>) {
        Vec::clear(self);
    }

    fn len(&self) -> usize {
        Vec::len(self)
    }

    fn segment_count(&self) -> usize {
        usize::from(!self.is_empty())
    }

    fn try_push_back(
        &mut self,
        _arena: &mut Arena<Vec<u8>>,
        mut buffer: Vec<u8>,
    ) -> Result<(), Vec<u8>> {
        if self.is_empty() {
            std::mem::swap(self, &mut buffer);
        } else {
            self.append(&mut buffer);
        }
        Ok(())
    }

    fn read_into(&mut self, _arena: &mut Arena<Vec<u8>>, destination: &mut Vec<u8>) -> usize {
        let count = self.len();
        if destination.is_empty() {
            std::mem::swap(destination, self);
        } else {
            destination.append(self);
        }
        count
    }

    fn read_owned(&mut self, _arena: &mut Arena<Vec<u8>>) -> Option<Vec<u8>> {
        (!self.is_empty()).then(|| std::mem::take(self))
    }

    fn pop_front(&mut self, arena: &mut Arena<Vec<u8>>) -> Option<Vec<u8>> {
        self.read_owned(arena)
    }
}

/// A receive payload whose representation remains private so ownership policy
/// can evolve without exposing the driver lifetime machinery to applications.
pub struct RecvBuffer<'d> {
    storage: RecvStorage<'d>,
}

enum RecvStorage<'d> {
    Owned(Vec<u8>),
    Compact(storage::Shared),
    Retained(dope::manifold::datagram::packet::Retained<'d>),
}

impl<'d> RecvBuffer<'d> {
    pub(crate) fn compact(bytes: storage::Shared) -> Self {
        Self {
            storage: RecvStorage::Compact(bytes),
        }
    }

    pub(crate) fn retained(bytes: dope::manifold::datagram::packet::Retained<'d>) -> Self {
        Self {
            storage: RecvStorage::Retained(bytes),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        self.as_ref()
    }

    pub fn len(&self) -> usize {
        self.as_ref().len()
    }

    pub fn is_empty(&self) -> bool {
        self.as_ref().is_empty()
    }

    /// Bytes held by the complete backing allocation. Compact fallback owners
    /// report their exact packet-level accepted-byte capacity; driver owners
    /// report the receive-slot capacity they retain.
    pub fn resident_bytes(&self) -> usize {
        match &self.storage {
            RecvStorage::Owned(bytes) => bytes.capacity(),
            RecvStorage::Compact(bytes) => bytes.resident_bytes(),
            RecvStorage::Retained(bytes) => bytes.resident_bytes(),
        }
    }

    pub fn into_owned(self) -> Vec<u8> {
        self.into_vec()
    }
}

impl receive_buffer::Sealed for RecvBuffer<'_> {}

impl std::fmt::Debug for RecvBuffer<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecvBuffer")
            .field("len", &self.len())
            .field("resident_bytes", &self.resident_bytes())
            .finish()
    }
}

impl AsRef<[u8]> for RecvBuffer<'_> {
    fn as_ref(&self) -> &[u8] {
        match &self.storage {
            RecvStorage::Owned(bytes) => bytes,
            RecvStorage::Compact(bytes) => bytes.as_ref(),
            RecvStorage::Retained(bytes) => bytes.as_ref(),
        }
    }
}

impl<'d> ReceiveBuffer for RecvBuffer<'d> {
    type Ready = ReadySegments;
    const SEGMENTED_READY: bool = true;

    fn copy_from_slice(bytes: &[u8]) -> Self {
        Self {
            storage: RecvStorage::Owned(bytes.to_vec()),
        }
    }

    fn from_vec(bytes: Vec<u8>) -> Self {
        Self {
            storage: RecvStorage::Owned(bytes),
        }
    }

    fn slice(&self, range: Range<usize>) -> Self {
        match &self.storage {
            RecvStorage::Owned(bytes) => Self::from_vec(bytes[range].to_vec()),
            RecvStorage::Compact(bytes) => Self::compact(
                bytes
                    .get(range)
                    .expect("receive range must remain within its compact owner"),
            ),
            RecvStorage::Retained(bytes) => Self::retained(
                bytes
                    .get(range)
                    .expect("receive range must remain within its driver owner"),
            ),
        }
    }

    fn into_range(self, range: Range<usize>) -> Self {
        match self.storage {
            RecvStorage::Owned(mut bytes) => {
                bytes.truncate(range.end);
                Self::from_vec(if range.start == 0 {
                    bytes
                } else {
                    bytes.split_off(range.start)
                })
            }
            RecvStorage::Compact(mut bytes) if range.end == bytes.len() => {
                if range.start != 0 {
                    assert!(bytes.try_advance(range.start));
                }
                Self::compact(bytes)
            }
            RecvStorage::Compact(bytes) => Self::compact(
                bytes
                    .get(range)
                    .expect("receive range must remain within its compact owner"),
            ),
            RecvStorage::Retained(bytes) => {
                Self::retained(bytes.into_range(range).unwrap_or_else(|_| {
                    unreachable!("receive range must remain within its driver owner")
                }))
            }
        }
    }

    fn into_suffix(self, offset: usize) -> Self {
        match self.storage {
            RecvStorage::Owned(mut bytes) => {
                if offset == 0 {
                    Self::from_vec(bytes)
                } else {
                    Self::from_vec(bytes.split_off(offset))
                }
            }
            RecvStorage::Compact(mut bytes) => {
                if offset != 0 {
                    assert!(bytes.try_advance(offset));
                }
                Self::compact(bytes)
            }
            RecvStorage::Retained(bytes) => {
                if offset == 0 {
                    Self::retained(bytes)
                } else {
                    let len = bytes.len();
                    Self::retained(bytes.into_range(offset..len).unwrap_or_else(|_| {
                        unreachable!("receive suffix must remain within its owner")
                    }))
                }
            }
        }
    }

    fn into_vec(self) -> Vec<u8> {
        match self.storage {
            RecvStorage::Owned(bytes) => bytes,
            RecvStorage::Compact(bytes) => bytes.as_ref().to_vec(),
            RecvStorage::Retained(bytes) => bytes.as_ref().to_vec(),
        }
    }
}

const _: () = assert!(size_of::<RecvBuffer<'static>>() <= 5 * size_of::<usize>());

impl<'d> ReadyBuffer<RecvBuffer<'d>> for ReadySegments {
    fn clear(&mut self, arena: &mut Arena<RecvBuffer<'d>>) {
        ReadySegments::clear(self, arena);
    }

    fn len(&self) -> usize {
        ReadySegments::len(self)
    }

    fn segment_count(&self) -> usize {
        ReadySegments::segment_count(self)
    }

    fn try_push_back(
        &mut self,
        arena: &mut Arena<RecvBuffer<'d>>,
        buffer: RecvBuffer<'d>,
    ) -> Result<(), RecvBuffer<'d>> {
        ReadySegments::push_back(self, arena, buffer)
    }

    fn read_into(&mut self, arena: &mut Arena<RecvBuffer<'d>>, destination: &mut Vec<u8>) -> usize {
        let count = self.len();
        while let Some(segment) = self.pop_front(arena) {
            destination.extend_from_slice(segment.as_ref());
        }
        count
    }

    fn read_owned(&mut self, arena: &mut Arena<RecvBuffer<'d>>) -> Option<Vec<u8>> {
        if self.len() == 0 {
            return None;
        }
        let first = self.pop_front(arena)?;
        if self.len() == 0 {
            return Some(first.into_vec());
        }
        let mut bytes = Vec::with_capacity(first.len().saturating_add(self.len()));
        bytes.extend_from_slice(first.as_ref());
        while let Some(segment) = self.pop_front(arena) {
            bytes.extend_from_slice(segment.as_ref());
        }
        Some(bytes)
    }

    fn pop_front(&mut self, arena: &mut Arena<RecvBuffer<'d>>) -> Option<RecvBuffer<'d>> {
        ReadySegments::pop_front(self, arena)
    }
}

const MAX_SEND_SEGMENTS: usize = 4096;
pub const INLINE_SEND_CAPACITY: usize = inline::CAPACITY;

#[repr(transparent)]
#[derive(Debug, Default)]
struct SendFlags(u8);

impl SendFlags {
    const FIN_MARKED: u8 = 1 << 0;
    const FIN_SENT: u8 = 1 << 1;
    const FIN_ACKED: u8 = 1 << 2;
    const RESET_SENT: u8 = 1 << 3;
    const STOP_EVENT_PENDING: u8 = 1 << 4;

    fn contains(&self, flag: u8) -> bool {
        self.0 & flag != 0
    }

    fn insert(&mut self, flag: u8) {
        self.0 |= flag;
    }

    fn remove(&mut self, flag: u8) {
        self.0 &= !flag;
    }

    fn clear(&mut self) {
        self.0 = 0;
    }
}

#[repr(transparent)]
#[derive(Debug)]
struct ReadyPrevious(u32);

impl ReadyPrevious {
    const NONE: u32 = u32::MAX;

    fn get(&self) -> Option<u32> {
        (self.0 != Self::NONE).then_some(self.0)
    }

    fn set(&mut self, previous: Option<u32>) {
        self.0 = previous.unwrap_or(Self::NONE);
    }
}

impl Default for ReadyPrevious {
    fn default() -> Self {
        Self(Self::NONE)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvError {
    TooManyRanges,
    OffsetOverflow,
}

impl_error!(RecvError {
    Self::TooManyRanges => "stream reassembly capacity exceeded",
    Self::OffsetOverflow => "stream offset overflow",
});

impl From<InsertError> for RecvError {
    fn from(error: InsertError) -> Self {
        match error {
            InsertError::TooManyRanges | InsertError::BufferFull => Self::TooManyRanges,
            InsertError::OffsetOverflow => Self::OffsetOverflow,
        }
    }
}

#[derive(Debug)]
pub struct RecvStream<B: ReceiveBuffer = Vec<u8>> {
    assembled: B::Ready,
    delivered_to: u64,
    highest_offset: u64,
    gaps: RangeBuffer<B>,
    final_size: Option<u64>,
    reset_error: Option<u64>,
}

impl<B: ReceiveBuffer> Default for RecvStream<B> {
    fn default() -> Self {
        Self {
            assembled: B::Ready::default(),
            delivered_to: 0,
            highest_offset: 0,
            gaps: RangeBuffer::default(),
            final_size: None,
            reset_error: None,
        }
    }
}

impl<B: ReceiveBuffer> RecvStream<B> {
    pub(crate) fn receive_plan<'a>(
        &self,
        arena: &Arena<B>,
        segments: &'a mut Vec<Range<u64>>,
        parts: &'a mut Vec<(u64, Range<usize>)>,
    ) -> crate::range_buffer::Plan<'a> {
        self.gaps.plan(arena, segments, parts)
    }

    pub(crate) fn receive_range_count(&self) -> usize {
        self.gaps.range_count()
    }

    pub(crate) fn release_ranges(&mut self, arena: &mut Arena<B>) {
        self.gaps.recycle(arena);
        self.assembled.clear(arena);
    }

    pub(crate) fn recycle(&mut self) {
        debug_assert_eq!(self.gaps.range_count(), 0);
        debug_assert_eq!(self.assembled.len(), 0);
        self.delivered_to = 0;
        self.highest_offset = 0;
        self.final_size = None;
        self.reset_error = None;
    }

    pub fn highest_offset(&self) -> u64 {
        self.highest_offset
    }

    pub(crate) fn insert(
        &mut self,
        arena: &mut Arena<B>,
        parts: &mut Vec<(u64, Range<usize>)>,
        offset: u64,
        data: B,
        fin: bool,
    ) -> Result<(), RecvError> {
        let end = offset
            .checked_add(u64::try_from(data.as_ref().len()).map_err(|_| RecvError::OffsetOverflow)?)
            .ok_or(RecvError::OffsetOverflow)?;
        self.gaps
            .insert_and_drain_into(
                arena,
                parts,
                offset,
                data,
                crate::range_buffer::InsertLimits::new(usize::MAX, MAX_RANGES),
                &mut self.assembled,
            )
            .map_err(RecvError::from)?;
        self.highest_offset = self.highest_offset.max(end);
        if fin {
            self.final_size = Some(end);
        }
        debug_assert!(self.assembled.segment_count() <= MAX_RECV_SEGMENTS || B::SEGMENTED_READY);
        Ok(())
    }

    /// Applies the metadata effect of a STREAM frame whose payload is proven
    /// to be erased by a later RESET_STREAM in the same packet. Applications
    /// cannot run during packet commit, so the payload itself never needs to
    /// escape the dispatch turn.
    pub(crate) fn observe_transient(
        &mut self,
        offset: u64,
        len: usize,
        fin: bool,
    ) -> Result<(), RecvError> {
        let end = offset
            .checked_add(u64::try_from(len).map_err(|_| RecvError::OffsetOverflow)?)
            .ok_or(RecvError::OffsetOverflow)?;
        self.highest_offset = self.highest_offset.max(end);
        if fin {
            self.final_size = Some(end);
        }
        Ok(())
    }

    pub(crate) fn read(&mut self, arena: &mut Arena<B>, dst: &mut Vec<u8>) -> usize {
        let n = self.assembled.read_into(arena, dst);
        self.delivered_to += n as u64;
        n
    }

    pub(crate) fn read_owned(&mut self, arena: &mut Arena<B>) -> Option<Vec<u8>> {
        let bytes = self.assembled.read_owned(arena)?;
        let n = bytes.len();
        self.delivered_to += n as u64;
        Some(bytes)
    }

    /// Transfers one contiguous receive owner without copying.
    pub(crate) fn read_buffer(&mut self, arena: &mut Arena<B>) -> Option<B> {
        let segment = self.assembled.pop_front(arena)?;
        self.delivered_to += segment.as_ref().len() as u64;
        Some(segment)
    }

    pub fn is_eof(&self) -> bool {
        matches!(self.final_size, Some(size) if size == self.delivered_to)
    }

    pub fn final_size(&self) -> Option<u64> {
        self.final_size
    }

    pub fn reset(&mut self, error_code: u64, final_size: u64) {
        self.reset_error = Some(error_code);
        self.final_size = Some(final_size);
        if final_size > self.highest_offset {
            self.highest_offset = final_size;
        }
    }

    pub fn reset_error(&self) -> Option<u64> {
        self.reset_error
    }
}

impl RecvStream<Vec<u8>> {
    fn insert_copy(
        &mut self,
        arena: &mut Arena<Vec<u8>>,
        parts: &mut Vec<(u64, Range<usize>)>,
        offset: u64,
        data: &[u8],
        fin: bool,
    ) -> Result<(), RecvError> {
        let end = offset
            .checked_add(u64::try_from(data.len()).map_err(|_| RecvError::OffsetOverflow)?)
            .ok_or(RecvError::OffsetOverflow)?;
        self.gaps
            .insert_copy_and_drain_into(
                arena,
                parts,
                offset,
                data,
                crate::range_buffer::InsertLimits::new(usize::MAX, MAX_RANGES),
                &mut self.assembled,
            )
            .map_err(RecvError::from)?;
        self.highest_offset = self.highest_offset.max(end);
        if fin {
            self.final_size = Some(end);
        }
        Ok(())
    }
}

impl<'d> RecvStream<RecvBuffer<'d>> {
    pub(crate) fn insert_retained(
        &mut self,
        arena: &mut Arena<RecvBuffer<'d>>,
        parts: &mut Vec<(u64, Range<usize>)>,
        offset: u64,
        data: RecvBuffer<'d>,
        fin: bool,
    ) -> Result<(), RecvError> {
        let end = offset
            .checked_add(u64::try_from(data.len()).map_err(|_| RecvError::OffsetOverflow)?)
            .ok_or(RecvError::OffsetOverflow)?;
        self.gaps
            .insert_retained_and_drain_into(
                arena,
                parts,
                offset,
                data,
                crate::range_buffer::InsertLimits::new(usize::MAX, MAX_RANGES),
                &mut self.assembled,
            )
            .map_err(RecvError::from)?;
        self.highest_offset = self.highest_offset.max(end);
        if fin {
            self.final_size = Some(end);
        }
        Ok(())
    }

    pub(crate) fn insert_compact(
        &mut self,
        arena: &mut Arena<RecvBuffer<'d>>,
        parts: &mut Vec<(u64, Range<usize>)>,
        offset: u64,
        original_len: usize,
        data: storage::Shared,
        fin: bool,
    ) -> Result<(), RecvError> {
        let end = offset
            .checked_add(u64::try_from(original_len).map_err(|_| RecvError::OffsetOverflow)?)
            .ok_or(RecvError::OffsetOverflow)?;
        self.gaps
            .insert_compact_and_drain_into(
                arena,
                parts,
                crate::range_buffer::InsertData::new(offset, original_len, data),
                crate::range_buffer::InsertLimits::new(usize::MAX, MAX_RANGES),
                &mut self.assembled,
            )
            .map_err(RecvError::from)?;
        self.highest_offset = self.highest_offset.max(end);
        if fin {
            self.final_size = Some(end);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SendBuffer {
    Inline(inline::Bytes),
    Owned(Vec<u8>),
    Retained(Bytes<Retained>),
}

impl SendBuffer {
    pub fn inline(bytes: &[u8]) -> Result<Self, CapacityError> {
        inline::Bytes::from_slice(bytes).map(Self::Inline)
    }

    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Inline(bytes) => bytes.as_slice(),
            Self::Owned(bytes) => bytes,
            Self::Retained(bytes) => bytes.as_slice(),
        }
    }

    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    pub fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }
}

impl AsRef<[u8]> for SendBuffer {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl From<Vec<u8>> for SendBuffer {
    fn from(bytes: Vec<u8>) -> Self {
        Self::Owned(bytes)
    }
}

impl From<Bytes<Retained>> for SendBuffer {
    fn from(bytes: Bytes<Retained>) -> Self {
        Self::Retained(bytes)
    }
}

#[derive(Debug, Default)]
pub struct SendStream {
    chunks: Cursor<SendBuffer>,
    spare: Vec<u8>,
    base_offset: u64,
    sent_rel: usize,
    flags: SendFlags,
    ready_previous: ReadyPrevious,
    stop_sending_error: Option<u64>,
}

impl SendStream {
    pub fn write(&mut self, data: &[u8]) -> bool {
        if data.is_empty() {
            return true;
        }
        if matches!(self.chunks.back(), Some(SendBuffer::Owned(_))) {
            return self
                .chunks
                .try_mutate_back(data.len(), |tail| {
                    let SendBuffer::Owned(tail) = tail else {
                        return false;
                    };
                    tail.extend_from_slice(data);
                    true
                })
                .unwrap_or(false);
        }
        let mut owned = std::mem::take(&mut self.spare);
        owned.extend_from_slice(data);
        self.write_buffer(owned.into())
    }

    pub fn write_buffer(&mut self, data: SendBuffer) -> bool {
        if data.is_empty() {
            return true;
        }
        if self.chunks.len().checked_add(data.len()).is_none() {
            return false;
        }
        if self.chunks.segment_count() >= MAX_SEND_SEGMENTS {
            self.coalesce();
        }
        self.chunks.try_push_back(data).is_ok()
    }

    pub fn mark_fin(&mut self) {
        self.flags.insert(SendFlags::FIN_MARKED);
    }

    pub fn has_pending(&self) -> bool {
        self.sent_rel < self.len()
            || (self.flags.contains(SendFlags::FIN_MARKED)
                && !self.flags.contains(SendFlags::FIN_SENT))
    }

    pub(crate) fn ready_previous(&self) -> Option<u32> {
        self.ready_previous.get()
    }

    pub(crate) fn set_ready_previous(&mut self, previous: Option<u32>) {
        self.ready_previous.set(previous);
    }

    pub(crate) fn stop_event_pending(&self) -> bool {
        self.flags.contains(SendFlags::STOP_EVENT_PENDING)
    }

    pub(crate) fn mark_stop_event_pending(&mut self) {
        self.flags.insert(SendFlags::STOP_EVENT_PENDING);
    }

    pub(crate) fn clear_stop_event_pending(&mut self) {
        self.flags.remove(SendFlags::STOP_EVENT_PENDING);
    }

    pub fn next_offset(&self) -> u64 {
        self.base_offset.saturating_add(self.sent_rel as u64)
    }

    pub fn unsent_len(&self) -> usize {
        self.chunks.len().saturating_sub(self.sent_rel)
    }

    pub fn would_fin(&self, take: usize) -> bool {
        self.flags.contains(SendFlags::FIN_MARKED)
            && self.sent_rel.saturating_add(take) >= self.len()
    }

    pub fn blocked(&self) -> bool {
        self.flags
            .contains(SendFlags::FIN_SENT | SendFlags::RESET_SENT)
    }

    pub fn range_available(&self, offset: u64, len: u64) -> bool {
        if len == 0 {
            return offset == self.next_offset();
        }
        if offset < self.base_offset {
            return false;
        }
        let Some(start) = usize::try_from(offset - self.base_offset).ok() else {
            return false;
        };
        let Some(len) = usize::try_from(len).ok() else {
            return false;
        };
        self.chunks.range_available(start, len)
    }

    pub fn append_range(&self, out: &mut Vec<u8>, offset: u64, len: usize) -> bool {
        if u64::try_from(len).is_err() || offset < self.base_offset {
            return false;
        }
        let Ok(offset) = usize::try_from(offset - self.base_offset) else {
            return false;
        };
        if len == 0 {
            return offset < self.chunks.len();
        }
        self.chunks.extend_range(offset, len, out)
    }

    pub fn advance_sent(&mut self, n: usize, fin_now: bool) {
        self.sent_rel += n;
        if fin_now {
            self.flags.insert(SendFlags::FIN_SENT);
        }
    }

    /// Applies one contiguous prefix proven by the delivery journal.
    ///
    /// The journal retains every out-of-order acknowledgement. Consequently
    /// this method never needs its own interval index and cannot release bytes
    /// still referenced by an in-flight or retryable delivery node.
    pub(crate) fn acknowledge_prefix(&mut self, offset: u64, len: usize, fin: bool) -> bool {
        if offset != self.base_offset || len > self.sent_rel || len > self.len() {
            return false;
        }
        self.discard_prefix(len);
        self.base_offset += len as u64;
        self.sent_rel -= len;
        if fin {
            self.flags.insert(SendFlags::FIN_ACKED);
        }
        true
    }

    pub fn is_fully_acked(&self) -> bool {
        self.flags.contains(SendFlags::FIN_ACKED) && self.chunks.is_empty()
    }

    pub(crate) fn recycle(&mut self) {
        self.chunks.clear();
        self.base_offset = 0;
        self.sent_rel = 0;
        self.flags.clear();
        self.ready_previous.set(None);
        self.stop_sending_error = None;
    }

    pub fn stop(&mut self, error_code: u64) {
        let final_size = self.next_offset();
        self.stop_sending_error = Some(error_code);
        self.chunks.clear();
        self.base_offset = final_size;
        self.sent_rel = 0;
    }

    pub fn stop_sending_error(&self) -> Option<u64> {
        self.stop_sending_error
    }

    pub fn mark_reset_sent(&mut self) {
        let final_size = self.next_offset();
        self.flags.insert(SendFlags::RESET_SENT);
        self.chunks.clear();
        self.base_offset = final_size;
        self.sent_rel = 0;
    }

    pub fn reset_sent(&self) -> bool {
        self.flags.contains(SendFlags::RESET_SENT)
    }

    pub(crate) fn reset_final_size(&self) -> u64 {
        debug_assert!(self.reset_sent());
        self.base_offset
    }

    fn len(&self) -> usize {
        self.chunks.len()
    }

    fn discard_prefix(&mut self, len: usize) {
        let Self { chunks, spare, .. } = self;
        chunks.consume_prefix_up_to(len, |segment| {
            if let SendBuffer::Owned(mut bytes) = segment {
                bytes.clear();
                if bytes.capacity() > spare.capacity() {
                    *spare = bytes;
                }
            }
        });
    }

    fn coalesce(&mut self) {
        let mut bytes = std::mem::take(&mut self.spare);
        let buffered_len = self.chunks.len();
        bytes.reserve(buffered_len);
        let appended = self.append_range(&mut bytes, self.base_offset, buffered_len);
        debug_assert!(appended);
        if !appended {
            bytes.clear();
            self.spare = bytes;
            return;
        }
        self.chunks.clear();
        self.chunks.try_push_back(SendBuffer::Owned(bytes)).unwrap();
    }
}

const _: () = assert!(size_of::<SendBuffer>() == 32);
const _: () = assert!(size_of::<SendStream>() == 112);
