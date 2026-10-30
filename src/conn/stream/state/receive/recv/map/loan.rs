use crate::conn::stream::recv::Source;
use crate::conn::stream::state::receive::Receive;
use crate::conn::stream::state::receive::recv::map::{DeliveryRead, Handle, Occupied};
use crate::conn::stream::state::streams;
use crate::conn::stream::{State, Streams};
use crate::stream::Recv;
use o3::{buffer, depot};
use std::num::NonZero;

/// The delivered owner and the occupied epoch charged for its bytes.
pub(in crate::conn) struct Held<B: Recv> {
    pub(super) buffer: B,
    pub(super) handle: Handle,
    pub(super) bytes: usize,
}

impl<B: Recv> Held<B> {
    pub(in crate::conn) fn into_parts(self) -> (B, Credit) {
        (
            self.buffer,
            Credit {
                handle: self.handle,
                bytes: self.bytes,
            },
        )
    }

    pub(in crate::conn) const fn len(&self) -> usize {
        self.bytes
    }
}

impl<B: Recv> AsRef<[u8]> for Held<B> {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

/// An affine balance derived only from a delivered owner or an existing balance.
#[derive(Debug)]
pub(in crate::conn) struct Credit {
    handle: Handle,
    bytes: usize,
}

impl Credit {
    pub(in crate::conn) const fn len(&self) -> usize {
        self.bytes
    }

    pub(in crate::conn) fn take_prefix(&mut self, bytes: NonZero<usize>) -> Option<Self> {
        let bytes = bytes.get();
        let remain = self.bytes.checked_sub(bytes)?;
        self.bytes = remain;
        Some(Self {
            handle: self.handle,
            bytes,
        })
    }

    pub(in crate::conn) fn try_merge(&mut self, other: Self) -> Result<(), Self> {
        self.try_admit(other).map(Merge::commit)
    }

    pub(in crate::conn) fn try_admit(&mut self, incoming: Self) -> Result<Merge<'_>, Self> {
        if self.handle != incoming.handle {
            return Err(incoming);
        }
        let Some(bytes) = self.bytes.checked_add(incoming.bytes) else {
            return Err(incoming);
        };
        Ok(Merge {
            target: self,
            incoming,
            bytes,
        })
    }

    /// Empty balances preserve merge identity but carry no liveness obligation.
    pub(in crate::conn) fn into_loan(self) -> Option<Loan> {
        NonZero::new(self.bytes).map(|bytes| Loan {
            handle: self.handle,
            bytes,
        })
    }
}

/// The original target and incoming reservation remain owned until commitment.
pub(in crate::conn) struct Merge<'target> {
    target: &'target mut Credit,
    incoming: Credit,
    bytes: usize,
}

impl Merge<'_> {
    pub(in crate::conn) const fn incoming_len(&self) -> usize {
        self.incoming.len()
    }

    pub(in crate::conn) fn into_input(self) -> Credit {
        self.incoming
    }

    pub(in crate::conn) fn commit(self) {
        self.target.bytes = self.bytes;
    }
}

/// A nonempty reservation keeps this exact occupied generation unreclaimable.
pub(in crate::conn) struct Loan {
    handle: Handle,
    bytes: NonZero<usize>,
}

impl Loan {
    pub(super) const fn handle(&self) -> Handle {
        self.handle
    }

    pub(super) fn bytes(self) -> usize {
        self.bytes.get()
    }

    pub(in crate::conn::stream) fn settle<
        const DOMAIN: u8,
        B: Recv,
        D: buffer::raw::Segment,
        const CONNECTION: bool,
    >(
        source: Source<'_, DOMAIN, B, D>,
    ) {
        let (conn, loan) = source.into_parts();
        let done = {
            let ctrl = &mut conn.control;
            let Streams { state, events } = &mut conn.streams;
            let local = state.local();
            let State {
                resident: table,
                receive: recv,
                ..
            } = state;
            let starts = recv.initial_stream_data;
            let map = &mut recv.map;
            // SAFETY: matching branded Receive retains the original machine
            // and its positive affine debt in Source. Map owns its unique origin;
            // published epochs can be recycled only through Reclaim after all
            // delivered debt returns. This exact epoch therefore remains live
            // in this original pool, whose exclusive borrow retains both planes.
            let entry =
                unsafe { depot::raw::Project::project(&mut map.core, *loan.handle().0.value()) };
            let slot = Occupied {
                entry,
                arena: &map.ranges,
            };
            let id = slot.id();
            let base = starts.credit(streams::Relative::new(id, local));
            DeliveryRead {
                slot,
                value: (),
                free: loan.bytes() as u64,
            }
            .finish(base, ctrl, table, events)
        };
        Receive::<'_, DOMAIN, B, D>::new(conn).finish::<_, CONNECTION>(done);
    }
}
