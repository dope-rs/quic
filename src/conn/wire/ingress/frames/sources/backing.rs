use std::marker;

use dope::manifold::network::datagram::packet;
use o3::buffer::storage::provided;
use o3::buffer::write::SpareExt as _;
use o3::buffer::{self, hold, storage, write};

use crate::errors::detail;
use crate::stream::{self, retain};

use crate::conn::wire::ingress::frames::sources::{Backing, Payload, Source};

pub(in crate::conn::wire::ingress) struct Copied<B>(marker::PhantomData<fn() -> B>);

impl<B> Copied<B> {
    pub(in crate::conn::wire::ingress) fn new() -> Self {
        Self(marker::PhantomData)
    }
}

impl<B: stream::Recv> Source<B> for Copied<B> {
    type Backing = Self;

    fn prepare<F>(self, _: usize, _: F) -> Result<Self::Backing, detail::Preparation>
    where
        F: FnOnce(&mut write::Spare<'_>) -> Result<(), detail::Copying>,
    {
        Ok(self)
    }
}

impl<B: stream::Recv> Backing<B> for Copied<B> {
    fn datagram(&self, payload: Payload<'_>) -> Result<B, detail::Backing> {
        B::try_copy(payload.bytes).map_err(detail::Backing::Capacity)
    }

    fn stream<'body>(
        &self,
        payload: Payload<'body>,
    ) -> Result<stream::Payload<'body, B>, detail::Backing> {
        Ok(stream::Payload::Borrowed(payload.bytes))
    }
}

pub(in crate::conn::wire::ingress) struct Retained<'a, 'd, P> {
    packet: &'a P,
    retainer: packet::Retainer<'d>,
    base: usize,
}

impl<'a, 'd, P> Retained<'a, 'd, P> {
    pub(in crate::conn::wire::ingress) fn new(
        packet: &'a P,
        retainer: packet::Retainer<'d>,
        base: usize,
    ) -> Self {
        Self {
            packet,
            retainer,
            base,
        }
    }
}

pub(in crate::conn::wire::ingress) enum Storage<A> {
    Driver { packet: A, base: usize },
    Compact(storage::Shared),
}

impl<A> Storage<A> {
    fn buffer<'d, const ADAPTIVE: bool>(
        &self,
        payload: Payload<'_>,
    ) -> Result<stream::RecvBuffer<'d, ADAPTIVE>, detail::Projection>
    where
        A: retain::Retain<'d>,
    {
        match self {
            Self::Driver { packet, base } => {
                let start =
                    base.checked_add(payload.wire.start)
                        .ok_or(detail::Projection::Start {
                            base: *base,
                            offset: payload.wire.start,
                        })?;
                let end = base
                    .checked_add(payload.wire.end)
                    .ok_or(detail::Projection::End {
                        base: *base,
                        offset: payload.wire.end,
                    })?;
                packet
                    .try_get(start..end)
                    .map_err(detail::Projection::Driver)
            }
            Self::Compact(bytes) => {
                let view = buffer::View::new(bytes)
                    .try_get(payload.compact)
                    .map_err(detail::Projection::Compact)?;
                let compact = view
                    .try_retain()
                    .map_err(detail::Projection::CompactRetain)?;
                Ok(stream::RecvBuffer::<ADAPTIVE>::compact(compact))
            }
        }
    }
}

impl<'a, 'd, P: packet::Backing, const ADAPTIVE: bool> Source<stream::RecvBuffer<'d, ADAPTIVE>>
    for Retained<'a, 'd, P>
where
    P::Storage: provided::Frozen<'d>,
    <P::Storage as provided::Frozen<'d>>::Account: retain::Retain<'d>,
{
    type Backing = Storage<<P::Storage as provided::Frozen<'d>>::Account>;

    fn prepare<F>(self, bytes: usize, fill: F) -> Result<Self::Backing, detail::Preparation>
    where
        F: FnOnce(&mut write::Spare<'_>) -> Result<(), detail::Copying>,
    {
        const POLICY: hold::Policy = hold::Policy::new(1, 4);
        let choice = POLICY.choose(bytes, || buffer::Residency::resident(self.packet.backing()));
        match choice {
            hold::Choice::Empty => {
                return Ok(Storage::Compact(storage::Shared::new()));
            }
            hold::Choice::Copy if ADAPTIVE => {}
            hold::Choice::Copy | hold::Choice::Share => match self.retainer.try_retain(self.packet)
            {
                Ok(packet) => {
                    return Ok(Storage::Driver {
                        packet,
                        base: self.base,
                    });
                }
                Err(error) if !ADAPTIVE => return Err(detail::Preparation::Retention(error)),
                Err(packet::Cause::Disabled | packet::Cause::Account(_)) => {}
            },
        }
        let mut compact = storage::Owned::try_with(bytes).map_err(detail::Preparation::Storage)?;
        let mut writer = compact.spare();
        fill(&mut writer).map_err(detail::Preparation::Copy)?;
        writer
            .try_complete()
            .map_err(detail::Preparation::Incomplete)?;
        Ok(Storage::Compact(compact.freeze()))
    }
}

impl<'d, A: retain::Retain<'d>, const ADAPTIVE: bool> Backing<stream::RecvBuffer<'d, ADAPTIVE>>
    for Storage<A>
{
    fn datagram(
        &self,
        payload: Payload<'_>,
    ) -> Result<stream::RecvBuffer<'d, ADAPTIVE>, detail::Backing> {
        self.buffer(payload).map_err(detail::Backing::Payload)
    }

    fn stream<'body>(
        &self,
        payload: Payload<'body>,
    ) -> Result<stream::Payload<'body, stream::RecvBuffer<'d, ADAPTIVE>>, detail::Backing> {
        Ok(stream::Payload::Owned(
            self.buffer(payload).map_err(detail::Backing::Payload)?,
        ))
    }
}
