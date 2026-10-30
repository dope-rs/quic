use std::{num, time};

use crate::runtime::routing::registry::Scope;
use crate::{
    conn, errors,
    runtime::{brand, mux},
    stream,
};
use conn::{id, scope};
use control::Control as _;
use mux::{auth, handler, protocol, router};
use protocol::control;
use scope::path;

#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct Batch {
    visited: usize,
    started: usize,
}

pub(crate) struct Sweep {
    batch: Batch,
    scanned: usize,
    next_cursor: u16,
    complete: bool,
}

impl Batch {
    pub const fn visited(self) -> usize {
        self.visited
    }

    pub const fn started(self) -> usize {
        self.started
    }
}

impl Sweep {
    pub(crate) const fn batch(&self) -> Batch {
        self.batch
    }

    pub(crate) const fn scanned(&self) -> usize {
        self.scanned
    }

    pub(crate) const fn next_cursor(&self) -> u16 {
        self.next_cursor
    }

    pub(crate) const fn is_complete(&self) -> bool {
        self.complete
    }
}

pub(crate) trait Local<
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    const DOMAIN: u8,
    B: stream::Recv,
>
{
    fn rotate(
        &mut self,
        handle: id::Handle<A::Identity, DOMAIN>,
        now: time::Instant,
    ) -> Result<path::Rotation, errors::Access>;

    fn sweep(&mut self, now: time::Instant, cursor: u16, budget: num::NonZero<u16>) -> Sweep;
}

impl<'a, 'tls, H, const DOMAIN: u8, B, A> Local<A, H, DOMAIN, B>
    for protocol::Io<'a, 'tls, H, DOMAIN, B, A>
where
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    B: stream::Recv,
{
    fn rotate(
        &mut self,
        handle: id::Handle<A::Identity, DOMAIN>,
        now: time::Instant,
    ) -> Result<path::Rotation, errors::Access> {
        self.with(handle, now, |mut scope| scope.path().rotate())
    }

    fn sweep(&mut self, now: time::Instant, cursor: u16, budget: num::NonZero<u16>) -> Sweep {
        let capacity = self.mux.as_ref().get_ref().state.registry.capacity();
        let start = usize::from(cursor);
        if self.mux.as_ref().get_ref().state.registry.len() == 0 || start >= capacity {
            return Sweep {
                batch: Batch::default(),
                scanned: 0,
                next_cursor: 0,
                complete: true,
            };
        }
        let end = start
            .saturating_add(usize::from(budget.get()))
            .min(capacity);
        let mut batch = Batch::default();
        let turn = router::Turn::new(self.mux.as_mut());
        let state = &mut *turn.state;
        brand::Token::with(|brand| {
            Scope::with(&mut state.registry, |mut slots| {
                for index in start..end {
                    let Some(key) = slots.resolve(index) else {
                        continue;
                    };
                    let rotation =
                        router::State::<A, H::Connection, DOMAIN, B>::trusted_in::<_, true>(
                            brand.reborrow(),
                            &mut slots,
                            key,
                            &mut state.binding,
                            now,
                            |mut slot| slot.conn.path().rotate(),
                        );
                    batch.visited += 1;
                    match rotation {
                        path::Rotation::Queued => {
                            batch.started += 1;
                        }
                        path::Rotation::Unavailable => {}
                    }
                }
            })
        });
        Sweep {
            batch,
            scanned: end - start,
            next_cursor: if end == capacity {
                0
            } else {
                cursor.wrapping_add(budget.get())
            },
            complete: end == capacity,
        }
    }
}
