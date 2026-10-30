pub(in crate::conn) mod bodies;
pub mod events;
pub(in crate::conn) mod frames;
pub(super) mod packet;
pub(in crate::conn) mod receiver;
mod retained;
mod retry;

use o3::buffer::{self, resident};

use std::time;

use crate::conn;
use crate::conn::wire::path;
use crate::stream;

#[repr(transparent)]
struct Context<const RECONCILE: bool>(u64);

impl<const RECONCILE: bool> Context<RECONCILE> {
    const EFFECT_BITS: u32 = 8;
    const EFFECT_MASK: u64 = u8::MAX as u64;
    const SLOT_BITS: u32 = 4;
    const SLOT_MASK: u64 = (1 << Self::SLOT_BITS) - 1;

    const fn new() -> Self {
        Self(0)
    }

    fn set_route(&mut self, route: Option<path::LocalCidKey>) {
        let bits = route.map_or(0, |key| {
            let slot = key.slot() + 1;
            ((u64::from(key.generation()) << Self::SLOT_BITS) | slot as u64) << Self::EFFECT_BITS
        });
        self.0 = bits | (self.0 & Self::EFFECT_MASK);
    }

    fn route(&self) -> Option<path::LocalCidKey> {
        let bits = self.0 >> Self::EFFECT_BITS;
        let slot = (bits & Self::SLOT_MASK) as usize;
        if slot == 0 {
            return None;
        }
        let epoch = (bits >> Self::SLOT_BITS) as u32;
        path::LocalCidKey::new(slot - 1, epoch)
    }

    fn record(&mut self, fx: conn::Effects) {
        if RECONCILE {
            let mut sum = conn::Effects::from_bits(self.0 as u8);
            sum.merge(fx);
            self.0 = (self.0 & !Self::EFFECT_MASK) | u64::from(sum.bits());
        }
    }

    fn effects(self) -> conn::Effects {
        conn::Effects::from_bits(self.0 as u8)
    }
}

pub struct Input<
    'a,
    const DOMAIN: u8,
    B: stream::Recv,
    const RECONCILE: bool = false,
    D: buffer::raw::Segment = resident::Shared<'a>,
> {
    connection: &'a mut conn::Machine<DOMAIN, B, D>,
    workspace: &'a mut conn::Workspace,
    context: Context<RECONCILE>,
}

impl<'a, const DOMAIN: u8, B: stream::Recv, const RECONCILE: bool, D: buffer::raw::Segment>
    Input<'a, DOMAIN, B, RECONCILE, D>
{
    pub(crate) fn finish<T>(self, value: T) -> conn::Ingress<T> {
        conn::Ingress::new(value, self.context.effects())
    }

    fn reject<T>(&mut self, error: conn::Error) -> Result<T, conn::Error> {
        if let Some(change) = self.connection.close(&error) {
            self.context.record(change.effects());
        }
        if matches!(error, conn::Error::Timing(_)) {
            self.context
                .record(conn::Effects::from_bits(conn::Effects::LIFECYCLE));
        }
        Err(error)
    }

    pub(crate) fn new(
        conn: &'a mut conn::Machine<DOMAIN, B, D>,
        work: &'a mut conn::Workspace,
    ) -> Self {
        Self {
            connection: conn,
            workspace: work,
            context: Context::new(),
        }
    }

    pub(crate) fn with_route(mut self, route: Option<path::LocalCidKey>) -> Self {
        self.context.set_route(route);
        self
    }

    pub fn recv_packet(
        &mut self,
        wire: &mut [u8],
        now: time::Instant,
        failure: impl FnMut(&rustls::Error),
    ) -> Result<(), conn::Error> {
        let mut sink = events::Context::new(failure);
        self.recv_with(wire, now, &mut sink)
    }

    /// Receives one packet with its original release and diagnostic observers.
    pub fn recv_with<E: events::Sink>(
        &mut self,
        wire: &mut [u8],
        now: time::Instant,
        sink: &mut E,
    ) -> Result<(), conn::Error> {
        receiver::Receiver::new(self, now, sink).run(wire, bodies::Copied)
    }
}

const _: () = {
    assert!(conn::MAX_ACTIVE_CONNECTION_IDS <= Context::<false>::SLOT_MASK as usize);
    assert!(
        std::mem::size_of::<Context<false>>() == std::mem::size_of::<Option<path::LocalCidKey>>()
    );
    assert!(std::mem::size_of::<Context<true>>() == std::mem::size_of::<Context<false>>());
};
const _: () = {
    type Baseline<'a> = (
        &'a mut conn::Machine<0, Vec<u8>>,
        &'a mut conn::Workspace,
        Option<path::LocalCidKey>,
    );

    assert!(
        std::mem::size_of::<Input<'static, 0, Vec<u8>, false>>()
            == std::mem::size_of::<Baseline<'static>>()
    );
    assert!(
        std::mem::align_of::<Input<'static, 0, Vec<u8>, false>>()
            == std::mem::align_of::<Baseline<'static>>()
    );
};
