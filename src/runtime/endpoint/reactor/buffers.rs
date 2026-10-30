use o3::buffer;
use std::net;

use crate::runtime::mux::handler::hook::writable;

#[repr(transparent)]
pub(in crate::runtime::endpoint) struct Entry<Q> {
    pub(in crate::runtime::endpoint) packet: Q,
}

pub(in crate::runtime::endpoint) type Queued<Q> = (net::SocketAddr, Entry<Q>);

pub(in crate::runtime::endpoint) struct Pending<Q, W: writable::Interest> {
    entry: Option<Queued<Q>>,
    interest: W::State,
}

pub(in crate::runtime::endpoint) struct Vacant<'slot, Q, W: writable::Interest> {
    pending: &'slot mut Pending<Q, W>,
}

impl<Q, W: writable::Interest> Pending<Q, W> {
    pub(super) const fn new() -> Self {
        Self {
            entry: None,
            interest: W::EMPTY,
        }
    }

    pub(in crate::runtime::endpoint) const fn is_some(&self) -> bool {
        self.entry.is_some()
    }

    pub(super) fn vacant(&mut self) -> Option<Vacant<'_, Q, W>> {
        if self.entry.is_some() {
            W::exchange(&mut self.interest, writable::Receipt::Ready);
            return None;
        }
        Some(Vacant { pending: self })
    }

    pub(super) fn take(&mut self) -> Option<(Queued<Q>, Vacant<'_, Q, W>)> {
        let entry = self.entry.take()?;
        Some((entry, Vacant { pending: self }))
    }

    pub(super) fn clear(&mut self) {
        self.entry = None;
        W::exchange(&mut self.interest, writable::Receipt::Idle);
    }
}

impl<Q, W: writable::Interest> Vacant<'_, Q, W> {
    pub(in crate::runtime::endpoint) fn insert(self, entry: Queued<Q>) {
        self.pending.entry = Some(entry);
    }

    pub(super) fn restore(self, entry: Queued<Q>) {
        W::exchange(&mut self.pending.interest, writable::Receipt::Ready);
        self.insert(entry);
    }

    pub(super) fn accepted(self) -> writable::Receipt {
        W::exchange(&mut self.pending.interest, writable::Receipt::Idle)
    }
}

impl<Q: AsRef<[u8]>> AsRef<[u8]> for Entry<Q> {
    fn as_ref(&self) -> &[u8] {
        self.packet.as_ref()
    }
}

impl<Q: buffer::Residency> buffer::Residency for Entry<Q> {
    fn resident(&self) -> usize {
        self.packet.resident()
    }
}
