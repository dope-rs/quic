use crate::{
    conn::{
        stream::state::receive::recv::map::{self, views},
        wire::ingress::frames,
    },
    stream,
};
use o3::alloc::VecExt as _;
use o3::depot::arena::linked::slots;
use o3::depot::{self};
use std::mem;

use crate::conn::stream::state::receive::recv::map::ready::Segments;

/// # Safety
/// Nonempty pushes consume exactly SEGMENTED claims from the original view owner.
pub unsafe trait Queue<B: stream::Recv<Ready = Self>>: Default {
    type Input<'body>: AsRef<[u8]>;
    const SEGMENTED: bool;
    fn try_prepare<'body>(
        payload: stream::Payload<'body, stream::Projection<B>>,
    ) -> Result<Self::Input<'body>, stream::Capacity>;
    fn append<'a>(
        view: &mut views::Write<'a, '_, B>,
        permit: &frames::CommitPermit<'_>,
        input: Self::Input<'_>,
        claim: impl FnOnce(B) -> slots::Live<map::Node<B>, &'a slots::Store<map::Node<B>>, map::Tag>,
    ) where
        B: 'a;
    fn clear(view: &mut views::Write<'_, '_, B>);
    fn try_reserve(&mut self, bytes: usize, ready: bool) -> Result<(), stream::Capacity>;
    fn push_back<'a>(
        view: &mut views::Write<'a, '_, B>,
        permit: &frames::CommitPermit<'_>,
        buffer: B,
        claim: impl FnOnce(B) -> slots::Live<map::Node<B>, &'a slots::Store<map::Node<B>>, map::Tag>,
    ) where
        B: 'a;
    fn read_into(
        view: &mut views::Write<'_, '_, B>,
        dst: &mut Vec<u8>,
    ) -> Result<usize, stream::Capacity>;
    fn read_owned(view: &mut views::Write<'_, '_, B>) -> Result<Option<Vec<u8>>, stream::Capacity>;
    fn pop_front(view: &mut views::Write<'_, '_, B>) -> Option<B>;
}

unsafe impl Queue<Vec<u8>> for Vec<u8> {
    type Input<'body> = stream::Payload<'body, stream::Projection<Vec<u8>>>;

    fn try_prepare<'body>(
        payload: stream::Payload<'body, stream::Projection<Vec<u8>>>,
    ) -> Result<Self::Input<'body>, stream::Capacity> {
        Ok(payload)
    }

    fn append<'a>(
        view: &mut views::Write<'a, '_, Vec<u8>>,
        permit: &frames::CommitPermit<'_>,
        input: Self::Input<'_>,
        claim: impl FnOnce(
            Vec<u8>,
        ) -> slots::Live<
            map::Node<Vec<u8>>,
            &'a slots::Store<map::Node<Vec<u8>>>,
            map::Tag,
        >,
    ) {
        match input {
            stream::Payload::Borrowed(bytes) => {
                view.entry.buffer.assembled.extend_from_slice(bytes)
            }
            stream::Payload::Owned(bytes) => {
                Self::push_back(view, permit, bytes.into_inner(), claim)
            }
        }
    }

    const SEGMENTED: bool = false;

    fn clear(view: &mut views::Write<'_, '_, Vec<u8>>) {
        view.entry.buffer.assembled.clear();
    }

    fn try_reserve(&mut self, bytes: usize, ready: bool) -> Result<(), stream::Capacity> {
        if self.is_empty() && !ready {
            return Ok(());
        }
        self.try_grow(bytes)
            .map_err(|error| stream::Capacity::Allocation {
                error,
                requested: bytes,
            })
    }

    fn push_back<'a>(
        view: &mut views::Write<'a, '_, Vec<u8>>,
        frames::CommitPermit { .. }: &frames::CommitPermit<'_>,
        mut buffer: Vec<u8>,
        _: impl FnOnce(
            Vec<u8>,
        ) -> slots::Live<
            map::Node<Vec<u8>>,
            &'a slots::Store<map::Node<Vec<u8>>>,
            map::Tag,
        >,
    ) {
        let ready = &mut view.entry.buffer.assembled;
        if ready.is_empty() {
            mem::swap(ready, &mut buffer);
        } else {
            ready.append(&mut buffer);
        }
    }

    fn read_into(
        view: &mut views::Write<'_, '_, Vec<u8>>,
        dst: &mut Vec<u8>,
    ) -> Result<usize, stream::Capacity> {
        let ready = &mut view.entry.buffer.assembled;
        let count = ready.len();
        if dst.is_empty() {
            mem::swap(dst, ready);
        } else {
            dst.try_grow(count)
                .map_err(|error| stream::Capacity::Allocation {
                    error,
                    requested: count,
                })?;
            dst.append(ready);
        }
        Ok(count)
    }

    fn read_owned(
        view: &mut views::Write<'_, '_, Vec<u8>>,
    ) -> Result<Option<Vec<u8>>, stream::Capacity> {
        Ok(Self::pop_front(view))
    }

    fn pop_front(view: &mut views::Write<'_, '_, Vec<u8>>) -> Option<Vec<u8>> {
        let ready = &mut view.entry.buffer.assembled;
        (!ready.is_empty()).then(|| mem::take(ready))
    }
}

// SAFETY: only Map lends these queue views; their filled topology cannot escape.
unsafe impl<'d, const ADAPTIVE: bool> Queue<stream::RecvBuffer<'d, ADAPTIVE>> for Segments {
    type Input<'body> = stream::Projection<stream::RecvBuffer<'d, ADAPTIVE>>;

    fn try_prepare<'body>(
        payload: stream::Payload<'body, Self::Input<'body>>,
    ) -> Result<Self::Input<'body>, stream::Capacity> {
        payload.try_owned()
    }

    fn append<'a>(
        view: &mut views::Write<'a, '_, stream::RecvBuffer<'d, ADAPTIVE>>,
        permit: &frames::CommitPermit<'_>,
        input: Self::Input<'_>,
        claim: impl FnOnce(
            stream::RecvBuffer<'d, ADAPTIVE>,
        ) -> slots::Live<
            map::Node<stream::RecvBuffer<'d, ADAPTIVE>>,
            &'a slots::Store<map::Node<stream::RecvBuffer<'d, ADAPTIVE>>>,
            map::Tag,
        >,
    ) where
        stream::RecvBuffer<'d, ADAPTIVE>: 'a,
    {
        Self::push_back(view, permit, input.into_inner(), claim);
    }

    const SEGMENTED: bool = true;

    fn clear(view: &mut views::Write<'_, '_, stream::RecvBuffer<'d, ADAPTIVE>>) {
        let ready = &mut view.entry.buffer.assembled;
        let mut queue = unsafe { view.arena.queue(&mut ready.queue) };
        while queue.pop_front().is_some() {}
        ready.bytes = 0;
    }

    fn try_reserve(&mut self, bytes: usize, _: bool) -> Result<(), stream::Capacity> {
        self.bytes
            .checked_add(bytes as u64)
            .ok_or(stream::Capacity::Overflow {
                current: self.bytes as usize,
                additional: bytes,
            })?;
        Ok(())
    }

    fn push_back<'a>(
        view: &mut views::Write<'a, '_, stream::RecvBuffer<'d, ADAPTIVE>>,
        frames::CommitPermit { .. }: &frames::CommitPermit<'_>,
        bytes: stream::RecvBuffer<'d, ADAPTIVE>,
        claim: impl FnOnce(
            stream::RecvBuffer<'d, ADAPTIVE>,
        ) -> slots::Live<
            map::Node<stream::RecvBuffer<'d, ADAPTIVE>>,
            &'a slots::Store<map::Node<stream::RecvBuffer<'d, ADAPTIVE>>>,
            map::Tag,
        >,
    ) where
        stream::RecvBuffer<'d, ADAPTIVE>: 'a,
    {
        let len = bytes.as_ref().len();
        if len == 0 {
            return;
        }
        let ready = &mut view.entry.buffer.assembled;
        unsafe { slots::Live::push_back(depot::raw::Proof::new((claim(bytes), &mut ready.queue))) };
        ready.bytes += len as u64;
    }

    fn read_into(
        view: &mut views::Write<'_, '_, stream::RecvBuffer<'d, ADAPTIVE>>,
        dst: &mut Vec<u8>,
    ) -> Result<usize, stream::Capacity> {
        let count = view.entry.buffer.assembled.bytes as usize;
        dst.try_grow(count)
            .map_err(|error| stream::Capacity::Allocation {
                error,
                requested: count,
            })?;
        while let Some(segment) = Self::pop_front(view) {
            dst.extend_from_slice(segment.as_ref());
        }
        Ok(count)
    }

    fn read_owned(
        view: &mut views::Write<'_, '_, stream::RecvBuffer<'d, ADAPTIVE>>,
    ) -> Result<Option<Vec<u8>>, stream::Capacity> {
        let ready = &mut view.entry.buffer.assembled;
        let count = ready.bytes as usize;
        let single = ready.queue.len() == 1;
        let queue = unsafe { view.arena.queue(&mut ready.queue) };
        let Some(mut first) = queue.front_entry() else {
            return Ok(None);
        };
        if single {
            let bytes = first.get_mut().bytes.try_take()?;
            first.discard();
            ready.bytes = 0;
            return Ok(Some(bytes));
        }
        let mut bytes = Vec::try_new(count).map_err(|error| stream::Capacity::Allocation {
            error,
            requested: count,
        })?;
        bytes.extend_from_slice(first.get_mut().bytes.as_ref());
        ready.bytes -= bytes.len() as u64;
        first.discard();
        while let Some(segment) = Self::pop_front(view) {
            bytes.extend_from_slice(segment.as_ref());
        }
        Ok(Some(bytes))
    }

    fn pop_front(
        view: &mut views::Write<'_, '_, stream::RecvBuffer<'d, ADAPTIVE>>,
    ) -> Option<stream::RecvBuffer<'d, ADAPTIVE>> {
        let ready = &mut view.entry.buffer.assembled;
        let node = unsafe { view.arena.queue(&mut ready.queue) }.pop_front()?;
        ready.bytes -= node.bytes().as_ref().len() as u64;
        Some(node.into_bytes())
    }
}
