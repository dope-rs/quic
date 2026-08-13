use std::{marker, ops};

use crate::conn;
use crate::conn::receive_workspace;
use crate::conn::streams;
use crate::stream;

pub(in crate::conn::ingress) trait Source<B: stream::ReceiveBuffer> {
    type Stream<'a>: streams::incoming::Incoming<B>
    where
        Self: 'a;

    fn prepare(
        &mut self,
        _escaping_bytes: usize,
        _materialize: impl FnOnce(&mut o3::buffer::storage::Owned) -> Result<(), conn::Error>,
    ) -> Result<(), conn::Error> {
        Ok(())
    }

    fn take_datagram(
        &mut self,
        range: ops::Range<usize>,
        payload: receive_workspace::ReceivePayloadPlan,
        bytes: &[u8],
    ) -> B;

    fn take_stream<'a>(
        &'a mut self,
        range: ops::Range<usize>,
        payload: receive_workspace::ReceivePayloadPlan,
        bytes: &'a [u8],
    ) -> Self::Stream<'a>;
}

pub(in crate::conn::ingress) struct Copied<B>(marker::PhantomData<fn() -> B>);

impl<B> Copied<B> {
    pub(in crate::conn::ingress) fn new() -> Self {
        Self(marker::PhantomData)
    }
}

impl<B: stream::ReceiveBuffer> Source<B> for Copied<B> {
    type Stream<'a>
        = streams::incoming::Copied<'a>
    where
        Self: 'a;

    fn take_datagram(
        &mut self,
        _range: ops::Range<usize>,
        _payload: receive_workspace::ReceivePayloadPlan,
        bytes: &[u8],
    ) -> B {
        B::copy_from_slice(bytes)
    }

    fn take_stream<'a>(
        &'a mut self,
        _range: ops::Range<usize>,
        _payload: receive_workspace::ReceivePayloadPlan,
        bytes: &'a [u8],
    ) -> Self::Stream<'a> {
        streams::incoming::Copied(bytes)
    }
}

pub(in crate::conn::ingress) struct Retained<'a, 'turn, 'retainer, 'd> {
    packet: &'a dope::manifold::datagram::packet::Frozen<'turn, 'd>,
    retainer: dope::manifold::datagram::packet::Retainer<'retainer, 'd>,
    body_offset: usize,
    retained: Option<dope::manifold::datagram::packet::Retained<'d>>,
    compact: Option<o3::buffer::storage::Shared>,
}

impl<'a, 'turn, 'retainer, 'd> Retained<'a, 'turn, 'retainer, 'd> {
    pub(in crate::conn::ingress) fn new(
        packet: &'a dope::manifold::datagram::packet::Frozen<'turn, 'd>,
        retainer: dope::manifold::datagram::packet::Retainer<'retainer, 'd>,
        body_offset: usize,
    ) -> Self {
        Self {
            packet,
            retainer,
            body_offset,
            retained: None,
            compact: None,
        }
    }
}

impl<'d> Source<stream::RecvBuffer<'d>> for Retained<'_, '_, '_, 'd> {
    type Stream<'a>
        = streams::incoming::RetainedIncoming<'d>
    where
        Self: 'a;

    fn prepare(
        &mut self,
        escaping_bytes: usize,
        materialize: impl FnOnce(&mut o3::buffer::storage::Owned) -> Result<(), conn::Error>,
    ) -> Result<(), conn::Error> {
        const MAX_RESIDENT_AMPLIFICATION: usize = 4;
        self.retained = if escaping_bytes != 0
            && self.packet.resident_bytes()
                <= escaping_bytes.saturating_mul(MAX_RESIDENT_AMPLIFICATION)
        {
            self.retainer.retain(self.packet, 0..self.packet.len())
        } else {
            None
        };
        if self.retained.is_some() {
            return Ok(());
        }
        if escaping_bytes == 0 {
            self.compact = Some(o3::buffer::storage::Shared::new());
            return Ok(());
        }
        let mut compact = o3::buffer::storage::Owned::try_with_capacity(escaping_bytes)
            .map_err(|_| conn::Error::StreamBufferExceeded)?;
        materialize(&mut compact)?;
        if compact.len() != escaping_bytes {
            return Err(conn::Error::StreamBufferExceeded);
        }
        self.compact = Some(compact.freeze());
        Ok(())
    }

    fn take_datagram(
        &mut self,
        range: ops::Range<usize>,
        payload: receive_workspace::ReceivePayloadPlan,
        _bytes: &[u8],
    ) -> stream::RecvBuffer<'d> {
        if let Some(packet) = &self.retained {
            let start = self
                .body_offset
                .checked_add(range.start)
                .expect("a parsed payload offset fits its packet");
            let end = self
                .body_offset
                .checked_add(range.end)
                .expect("a parsed payload end fits its packet");
            return stream::RecvBuffer::retained(
                packet
                    .get(start..end)
                    .expect("a parsed payload range remains within its retained packet"),
            );
        }
        stream::RecvBuffer::compact(
            self.compact
                .as_ref()
                .expect("a compact receive source was prepared before commit")
                .get(payload.compact_range())
                .expect("the receive plan bounded every compact datagram"),
        )
    }

    fn take_stream<'a>(
        &'a mut self,
        range: ops::Range<usize>,
        payload: receive_workspace::ReceivePayloadPlan,
        bytes: &'a [u8],
    ) -> Self::Stream<'a> {
        if self.retained.is_some() {
            streams::incoming::RetainedIncoming::Driver(self.take_datagram(range, payload, bytes))
        } else {
            streams::incoming::RetainedIncoming::Compact {
                bytes: self
                    .compact
                    .as_ref()
                    .expect("a compact receive source was prepared before commit")
                    .get(payload.compact_range())
                    .expect("the receive plan bounded every compact stream frame"),
                original_len: bytes.len(),
            }
        }
    }
}
